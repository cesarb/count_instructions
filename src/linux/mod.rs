use std::sync::Mutex;
use std::{panic, thread};

use core::cmp::Ordering;
use core::hint::black_box;
use core::mem::{forget, size_of};
use core::pin::pin;
use core::ptr::write_volatile;

use rustix::fd::AsRawFd;
use rustix::io::{read, retry_on_intr, write};
use rustix::pipe::{pipe_with, PipeFlags};
use rustix::process::{
    kill_process, set_ptracer, waitid, PTracer, Pid, Signal, WaitId, WaitidOptions, WaitidStatus,
};
use rustix::thread::gettid;

use super::{Address, Instruction};

mod ptrace_self;

use ptrace_self::{trace, TraceToken, STATE_COUNT, STATE_INIT, STATE_READY, STATE_STOP};

static TRACE_MUTEX: Mutex<TraceToken> = Mutex::new(TraceToken);

pub fn count_instructions<F, T, C>(f: F, mut counter: C) -> std::io::Result<T>
where
    F: FnOnce() -> T,
    C: FnMut(&Instruction) + Send,
{
    let mut state = pin!(STATE_INIT);
    let state_addr = state.as_ref().get_ref() as *const _ as libc::c_ulong;
    let mut write_state = |data| unsafe {
        // SAFETY: the result of casting a reference to a pointer is valid and properly aligned.
        // SAFETY: the tracer will only read this value while this thread is in a stopped state.
        write_volatile(state.as_mut().get_mut(), data);
    };

    thread::scope(|s| {
        let tid = gettid().as_raw_nonzero().get() as libc::pid_t;
        let (control_read, control_write) = pipe_with(PipeFlags::CLOEXEC)?;
        let (data_read, data_write) = pipe_with(PipeFlags::CLOEXEC)?;
        let (ready_read, ready_write) = pipe_with(PipeFlags::CLOEXEC)?;

        let child_close_fds = [
            control_read.as_raw_fd(),
            data_read.as_raw_fd(),
            ready_write.as_raw_fd(),
        ];
        let helper = thread::Builder::new().spawn_scoped(s, move || {
            let mut guard = TRACE_MUTEX.lock().unwrap();

            struct PidGuard(Pid);

            impl PidGuard {
                #[inline]
                fn get(&self) -> Pid {
                    self.0
                }

                fn wait(self) -> rustix::io::Result<WaitidStatus> {
                    let result = waitid(WaitId::Pid(self.0), WaitidOptions::EXITED);
                    forget(self);
                    Ok(result?.unwrap())
                }
            }

            impl Drop for PidGuard {
                fn drop(&mut self) {
                    let _ = kill_process(self.0, Signal::Kill);
                    let _ = waitid(WaitId::Pid(self.0), WaitidOptions::EXITED);
                }
            }

            assert!(tid > 0);
            let pid = unsafe {
                // SAFETY: the child will only use async-signal-safe functions from libc or raw system calls.
                let pid = libc::fork();
                match pid.cmp(&0) {
                    Ordering::Equal => {
                        // SAFETY: this runs in a forked child of a multithreaded program, so only
                        // async-signal-safe functions from libc or raw system calls can be used here.
                        // SAFETY: all the pipe fds were inherited before being closed, because they
                        // are closed after either the fork() call or the join of the forking thread.
                        for fd in child_close_fds {
                            libc::close(fd);
                        }
                        // SAFETY: the state variable outlives the thread scope, and the helper
                        // thread within that scope always waits for this child process to exit.
                        // SAFETY: the tracer will only read it while the thread is in a stopped state.
                        libc::_exit(
                            match trace(
                                tid,
                                state_addr,
                                control_write.as_raw_fd(),
                                data_write.as_raw_fd(),
                                ready_read.as_raw_fd(),
                                &mut guard,
                            ) {
                                Ok(_) => libc::EXIT_SUCCESS,
                                Err(_) => libc::EXIT_FAILURE,
                            },
                        );
                    }
                    Ordering::Greater => {
                        // SAFETY: pid is > 0
                        PidGuard(Pid::from_raw_unchecked(pid))
                    }
                    Ordering::Less => return Err(std::io::Error::last_os_error()),
                }
            };

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
        retry_on_intr(|| read(&control_read, &mut [0]))?;

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
