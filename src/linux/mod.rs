use std::os::fd::AsRawFd;
use std::panic;
use std::sync::Mutex;
use std::thread;

use core::cmp::Ordering;
use core::hint::black_box;
use core::mem::{drop, forget, size_of};
use core::pin::pin;
use core::ptr::{from_ref, write_volatile};

use rustix::io::{read, retry_on_intr, write};
use rustix::pipe::{PipeFlags, pipe_with};
use rustix::process::{
    PTracer, Pid, Signal, WaitId, WaitIdOptions, WaitIdStatus, kill_process, set_ptracer, waitid,
};

use super::{Address, Instruction};

mod fd;
mod ptrace_self;

use fd::RawOwnedFd;
use ptrace_self::{STATE_COUNT, STATE_INIT, STATE_READY, STATE_STOP, TraceToken, trace};

static TRACE_MUTEX: Mutex<TraceToken> = Mutex::new(TraceToken);

pub fn count_instructions<F, T, C>(f: F, mut counter: C) -> std::io::Result<T>
where
    F: FnOnce() -> T,
    C: FnMut(&Instruction) + Send,
{
    let mut state = pin!(STATE_INIT);
    let state_addr = from_ref(state.as_ref().get_ref()) as libc::c_ulong;
    // SAFETY: the result of casting a reference to a pointer is valid and properly aligned.
    // SAFETY: the tracer will only read this value while this thread is in a stopped state.
    let mut write_state = |data| unsafe { write_volatile(state.as_mut().get_mut(), data) };

    let (control_read, control_write) = pipe_with(PipeFlags::CLOEXEC)?;
    let (data_read, data_write) = pipe_with(PipeFlags::CLOEXEC)?;
    let (ready_read, ready_write) = pipe_with(PipeFlags::CLOEXEC)?;

    // These file descriptors will be used from the child of the fork(),
    // which must use only async-signal-safe functions, but `OwnedFd`
    // might use functions which are not async-signal-safe.
    let control_read = RawOwnedFd::from(control_read);
    let control_write = RawOwnedFd::from(control_write);
    let data_read = RawOwnedFd::from(data_read);
    let data_write = RawOwnedFd::from(data_write);
    let ready_read = RawOwnedFd::from(ready_read);
    let ready_write = RawOwnedFd::from(ready_write);

    // The read end of the control pipe is referenced by both threads.
    // Borrow it here, to ensure it can be dropped only after the scope.
    let control_read = &control_read;

    thread::scope(|s| {
        // SAFETY: gettid() is safe
        let traced_tid = unsafe { libc::gettid() };
        assert!(traced_tid > 0);

        let helper = thread::Builder::new().spawn_scoped(s, move || {
            let mut guard = TRACE_MUTEX.lock().unwrap();

            let pid = {
                // SAFETY: the child will only use async-signal-safe functions from libc
                // or raw system calls.
                let pid = unsafe { libc::fork() };
                match pid.cmp(&0) {
                    Ordering::Equal => {
                        // This block runs in a forked child of a multithreaded program, so only
                        // async-signal-safe functions from libc or raw system calls can be used here.

                        // Close the unused end of the pipes.
                        // SAFETY: `control_read` will only be closed in the parent process
                        // after the `thread::scope` ends, which means it's still open here.
                        // SAFETY: nothing else in this child acts on this file descriptor.
                        let _ = unsafe { libc::close(control_read.as_raw_fd()) };
                        drop(data_read);
                        drop(ready_write);

                        // SAFETY: the state variable outlives the thread scope, and the helper
                        // thread within that scope always waits for this child process to exit.
                        // SAFETY: the tracer will only read it while the thread is in a stopped state.
                        unsafe {
                            libc::_exit(
                                match trace(
                                    traced_tid,
                                    state_addr,
                                    control_write,
                                    data_write,
                                    ready_read,
                                    &mut guard,
                                ) {
                                    Ok(()) => libc::EXIT_SUCCESS,
                                    Err(_) => libc::EXIT_FAILURE,
                                },
                            );
                        }
                    }
                    Ordering::Greater => {
                        // SAFETY: pid is > 0
                        PidGuard(unsafe { Pid::from_raw_unchecked(pid) })
                    }
                    Ordering::Less => return Err(std::io::Error::last_os_error()),
                }
            };

            // Close the unused end of the pipes.
            drop(control_write);
            drop(data_write);
            drop(ready_read);

            // Necessary when "restricted ptrace" mode is enabled.
            set_ptracer(PTracer::ProcessID(pid.get()))?;
            retry_on_intr(|| write(&ready_write, &[0]))?;
            drop(ready_write);

            // Wait for child PTRACE_SEIZE call before releasing the mutex.
            let mut buf = [0; size_of::<Address>()];
            let size = retry_on_intr(|| read(&data_read, &mut buf))?;
            drop(guard);
            assert_eq!(size, buf.len());

            loop {
                let size = retry_on_intr(|| read(&data_read, &mut buf))?;
                if size == 0 {
                    break;
                }
                assert_eq!(size, buf.len());

                let address = Address::from_ne_bytes(buf);
                let instruction = Instruction::new(address);
                counter(&instruction);
            }
            drop(data_read);

            if pid.wait()?.exit_status() == Some(0) {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "error in tracer",
                ))
            }
        })?;

        write_state(STATE_READY);
        retry_on_intr(|| read(control_read, &mut [0]))?;

        write_state(STATE_COUNT);
        let f = black_box(f);
        let result = f();
        let result = black_box(result);
        write_state(STATE_STOP);

        match helper.join() {
            Ok(Ok(())) => Ok(result),
            Ok(Err(err)) => Err(err),
            Err(e) => panic::resume_unwind(e),
        }
    })
}

struct PidGuard(Pid);

impl PidGuard {
    #[inline]
    fn get(&self) -> Pid {
        self.0
    }

    fn wait(self) -> rustix::io::Result<WaitIdStatus> {
        let result = waitid(WaitId::Pid(self.0), WaitIdOptions::EXITED);
        forget(self);
        Ok(result?.unwrap())
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        let _ = kill_process(self.0, Signal::KILL);
        let _ = waitid(WaitId::Pid(self.0), WaitIdOptions::EXITED);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example() {
        #[inline(never)]
        fn add(left: usize, right: usize) -> usize {
            left + right
        }

        #[inline(never)]
        fn count() -> std::vec::Vec<Address> {
            let mut addresses = std::vec::Vec::new();
            let result = count_instructions(
                || add(2, 2),
                |instruction| addresses.push(instruction.address()),
            )
            .unwrap();
            assert_eq!(result, 4);
            assert!(!addresses.is_empty());
            addresses
        }

        #[inline(never)]
        fn count_other() -> std::vec::Vec<Address> {
            let mut addresses = std::vec::Vec::new();
            count_instructions(|| (), |instruction| addresses.push(instruction.address())).unwrap();
            assert!(!addresses.is_empty());
            addresses
        }

        let first = count();
        let second = count();
        let third = count_other();
        assert_eq!(first, second);
        assert_ne!(first, third);
    }
}
