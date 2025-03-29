// Code in this file should be treated as #![no_std]; it should only use core and libc,
// and must only use async-signal-safe functions or raw system calls.

#[allow(clippy::wildcard_imports)]
use libc::*;

use super::Address;
use super::fd::RawOwnedFd;
use core::mem::MaybeUninit;
use std::os::fd::AsRawFd;

pub const STATE_INIT: c_ulong = 0;
pub const STATE_READY: c_ulong = 1;
pub const STATE_COUNT: c_ulong = 2;
pub const STATE_STOP: c_ulong = 3;

pub struct TraceToken;

#[derive(Debug)]
struct RunningTracee {
    pid: pid_t,
    in_syscall: bool,
}

#[derive(Debug)]
struct StoppedTracee {
    pid: pid_t,
    stop: StoppedState,
}

impl RunningTracee {
    #[inline]
    unsafe fn new(pid: pid_t) -> RunningTracee {
        RunningTracee {
            pid,
            in_syscall: false,
        }
    }

    #[inline]
    unsafe fn stopped(self, stop: StoppedState) -> StoppedTracee {
        StoppedTracee {
            pid: self.pid,
            stop,
        }
    }
}

impl StoppedTracee {
    #[inline]
    unsafe fn restarted(self) -> RunningTracee {
        RunningTracee {
            pid: self.pid,
            in_syscall: self.stop == StoppedState::SyscallEnter,
        }
    }
}

#[inline]
fn errno() -> c_int {
    // SAFETY: reading errno is async-signal-safe
    // SAFETY: __errno_location() always points to this thread's errno
    unsafe { *__errno_location() }
}

unsafe fn sys_ptrace(
    request: c_uint,
    pid: pid_t,
    addr: c_ulong,
    data: c_ulong,
) -> Result<c_long, c_int> {
    // SAFETY: calling the system call directly instead of using the wrapper,
    // which is not in the async-signal-safe list
    // SAFETY: the type of the system call arguments is four longs, with
    // the first two being signed and the last two being unsigned
    let ret = unsafe { syscall(SYS_ptrace, request as c_long, pid as c_long, addr, data) };
    if ret < 0 { Err(errno()) } else { Ok(ret) }
}

// This function runs in a forked child of a multithreaded program, so only
// async-signal-safe functions from libc or raw system calls can be used here.
#[allow(clippy::needless_pass_by_value)]
pub unsafe fn trace(
    pid: pid_t,
    state_addr: c_ulong,
    control_fd: RawOwnedFd,
    data_fd: RawOwnedFd,
    ready_fd: RawOwnedFd,
    _token: &mut TraceToken,
) -> Result<(), c_int> {
    wait_for_set_ptracer(ready_fd)?;

    // SAFETY: the pid is for a thread in the parent process of the fork,
    // and in the unlikely case it isn't, the `read()` below will detect
    // it before anything else is done with the target thread.
    unsafe {
        sys_ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESYSGOOD as c_ulong)?;
        sys_ptrace(PTRACE_INTERRUPT, pid, 0, 0)?;
    }

    // Tell the helper thread that the target thread has been attached.
    // This also detects the very unlikely case of the parent process
    // having died and the thread pid having been reused before the
    // ptrace attach above. In that case, this will return Err(EPIPE)
    // which will lead to this process exiting and implicitly detaching.
    write_data(&data_fd, 0)?;

    // SAFETY: the pid is a thread being traced
    let mut tracee = wait_for_stop(unsafe { RunningTracee::new(pid) })?;

    // Fast skip until ready.
    // SAFETY: the address points to the pinned state value
    while unsafe { ptrace_peek(&tracee, state_addr)? } < STATE_READY {
        tracee = wait_for_stop(ptrace_restart(tracee, PTRACE_SYSCALL)?)?;
    }

    // The thread is stopped at or before the read of the pipe, allow it past that point.
    write_control(control_fd)?;

    // Skip over read of control pipe.
    while tracee.stop != StoppedState::SyscallExit {
        tracee = wait_for_stop(ptrace_restart(tracee, PTRACE_SYSCALL)?)?;
    }

    // Single step until start of counted region.
    // SAFETY: the address points to the pinned state value
    while unsafe { ptrace_peek(&tracee, state_addr)? } < STATE_COUNT {
        tracee = wait_for_stop(ptrace_restart(tracee, PTRACE_SINGLESTEP)?)?;
    }

    // Single step until end of counted region.
    // SAFETY: the address points to the pinned state value
    while unsafe { ptrace_peek(&tracee, state_addr)? } < STATE_STOP {
        if let StoppedState::SingleStep(addr) = tracee.stop {
            write_data(&data_fd, addr)?;
        }
        tracee = wait_for_stop(ptrace_restart(tracee, PTRACE_SINGLESTEP)?)?;
    }

    // Release the thread.
    ptrace_restart(tracee, PTRACE_DETACH)?;

    Ok(())
}

unsafe fn ptrace_peek(tracee: &StoppedTracee, addr: c_ulong) -> Result<c_ulong, c_int> {
    let pid = tracee.pid;
    let mut data = MaybeUninit::uninit();
    // SAFETY: the pid is a thread being traced, which is in ptrace-stop
    // SAFETY: the address is to a pinned value, and the thread owning it
    // will send SIGKILL to this process before dropping the pinned value
    // SAFETY: the data pointer points to enough space for an unsigned long
    unsafe {
        sys_ptrace(PTRACE_PEEKDATA, pid, addr, data.as_mut_ptr() as c_ulong)?;
    }
    // SAFETY: PTRACE_PEEKDATA writes a c_ulong to the data pointer
    Ok(unsafe { data.assume_init() })
}

/// # Safety
///
/// The pid must be a thread being traced, which is in ptrace-stop.
unsafe fn ptrace_getsiginfo(pid: pid_t) -> Result<siginfo_t, c_int> {
    let mut siginfo = MaybeUninit::uninit();
    // SAFETY: the pid is a thread being traced, which is in ptrace-stop
    // SAFETY: the data pointer points to enough space for a siginfo_t
    unsafe {
        sys_ptrace(PTRACE_GETSIGINFO, pid, 0, siginfo.as_mut_ptr() as c_ulong)?;
    }
    // SAFETY: PTRACE_GETSIGINFO fills the siginfo_t at the data pointer
    Ok(unsafe { siginfo.assume_init() })
}

fn ptrace_restart(tracee: StoppedTracee, request: c_uint) -> Result<RunningTracee, c_int> {
    let request = if request == PTRACE_DETACH {
        PTRACE_DETACH
    } else {
        match tracee.stop {
            StoppedState::SyscallEnter => PTRACE_SYSCALL,
            StoppedState::Group => PTRACE_LISTEN,
            _ => request,
        }
    };

    let sig = if let StoppedState::Signal(sig) = tracee.stop {
        sig as c_ulong
    } else {
        0
    };

    // assert!() cannot be used here, because it's not async-signal-safe
    if !matches!(
        request,
        PTRACE_CONT | PTRACE_LISTEN | PTRACE_DETACH | PTRACE_SYSCALL | PTRACE_SINGLESTEP
    ) {
        return Err(EINVAL);
    }

    // SAFETY: the pid is a thread being traced, which is in ptrace-stop
    // SAFETY: the signal is the one which entered the signal-delivery-stop
    unsafe {
        sys_ptrace(request, tracee.pid, 0, sig)?;
    }
    // SAFETY: the thread being traced is now running (request was a restart)
    Ok(unsafe { tracee.restarted() })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoppedState {
    SyscallEnter,
    SyscallExit,
    Event,
    Group,
    Signal(c_int),
    SingleStep(usize),
}

/// Determines the stopped state of the tracee.
///
/// # Safety
///
/// The pid must be a thread being traced, which is in ptrace-stop.
unsafe fn stopped_state(
    status: c_int,
    pid: pid_t,
    in_syscall: bool,
) -> Result<StoppedState, c_int> {
    let sig = WSTOPSIG(status);
    let stop = if sig == SIGTRAP | 0x80 {
        if in_syscall {
            StoppedState::SyscallExit
        } else {
            StoppedState::SyscallEnter
        }
    } else if sig == SIGTRAP {
        if status >> 16 != 0 {
            StoppedState::Event
        } else {
            // SAFETY: the target thread is in ptrace-stop
            let siginfo = unsafe { ptrace_getsiginfo(pid)? };
            if siginfo.si_code > 0 {
                // SAFETY: the stop signal is `SIGTRAP`, which has `si_addr`
                let addr = unsafe { siginfo.si_addr() };
                StoppedState::SingleStep(addr as usize)
            } else {
                StoppedState::Signal(sig)
            }
        }
    } else if status >> 16 == PTRACE_EVENT_STOP {
        StoppedState::Group
    } else {
        StoppedState::Signal(sig)
    };
    Ok(stop)
}

fn wait_for_stop(tracee: RunningTracee) -> Result<StoppedTracee, c_int> {
    let mut status = 0;
    loop {
        // SAFETY: `waitpid()` is async-signal-safe
        // SAFETY: the pid is a thread being traced; the status pointer is valid
        let ret = unsafe { waitpid(tracee.pid, &raw mut status, __WALL) };
        if ret < 0 {
            let err = errno();
            if err != EINTR {
                return Err(err);
            }
        } else if ret == tracee.pid {
            break;
        } else {
            return Err(ECHILD);
        }
    }

    if WIFSTOPPED(status) {
        // SAFETY: the pid is a thread being traced, which is in ptrace-stop
        let stop = unsafe { stopped_state(status, tracee.pid, tracee.in_syscall)? };
        // SAFETY: the thread being traced is in ptrace-stop
        Ok(unsafe { tracee.stopped(stop) })
    } else {
        Err(ECHILD)
    }
}

#[allow(clippy::cast_sign_loss)]
fn retry_pipe_on_intr<F>(mut f: F, len: usize) -> Result<(), c_int>
where
    F: FnMut() -> ssize_t,
{
    loop {
        let ret = f();
        if ret < 0 {
            let err = errno();
            if err != EINTR {
                break Err(err);
            }
        } else if ret as usize == len {
            break Ok(());
        } else {
            break Err(EPIPE);
        }
    }
}

/// Waits for and reads one byte on the ready pipe, and closes it.
#[allow(clippy::needless_pass_by_value)]
fn wait_for_set_ptracer(ready_fd: RawOwnedFd) -> Result<(), c_int> {
    let mut buf: [u8; 1] = [0];
    let len = buf.len();
    retry_pipe_on_intr(
        // SAFETY: `read()` is async-signal-safe
        // SAFETY: the `fd` is a valid open file descriptor
        // SAFETY: the buffer is mutable and has `len` bytes
        || unsafe { read(ready_fd.as_raw_fd(), (&raw mut buf).cast(), len) },
        len,
    )
}

/// Writes one byte to the control pipe, and closes it.
#[allow(clippy::needless_pass_by_value)]
fn write_control(control_fd: RawOwnedFd) -> Result<(), c_int> {
    let buf: [u8; 1] = [0];
    let len = buf.len();
    retry_pipe_on_intr(
        // SAFETY: `write()` is async-signal-safe
        // SAFETY: the `fd` is a valid open file descriptor
        // SAFETY: the buffer is readable and has `len` bytes
        || unsafe { write(control_fd.as_raw_fd(), (&raw const buf).cast(), len) },
        len,
    )
}

/// Writes one address to the data pipe.
fn write_data(data_fd: &RawOwnedFd, address: Address) -> Result<(), c_int> {
    let buf = address.to_ne_bytes();
    let len = buf.len();
    retry_pipe_on_intr(
        // SAFETY: `write()` is async-signal-safe
        // SAFETY: the `fd` is a valid open file descriptor
        // SAFETY: the buffer is readable and has `len` bytes
        || unsafe { write(data_fd.as_raw_fd(), (&raw const buf).cast(), len) },
        len,
    )
}
