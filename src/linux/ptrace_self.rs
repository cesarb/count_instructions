// Code in this file should be treated as #![no_std]; it should only use core and libc,
// and must only use async-signal-safe functions or raw system calls.

use super::Address;
use super::fd::RawOwnedFd;
use core::mem::MaybeUninit;
use libc::*;
use std::os::fd::AsRawFd;

pub const STATE_INIT: c_ulong = 0;
pub const STATE_READY: c_ulong = 1;
pub const STATE_COUNT: c_ulong = 2;
pub const STATE_STOP: c_ulong = 3;

pub struct TraceToken;

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
pub unsafe fn trace(
    pid: pid_t,
    state_addr: c_ulong,
    control_fd: RawOwnedFd,
    data_fd: &RawOwnedFd,
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
    write_data(data_fd, 0)?;

    let mut stop = StopState::Running;
    // SAFETY: the pid is a thread being traced
    unsafe {
        wait_for_stop(pid, &mut stop)?;
    }

    // Fast skip until ready.
    // SAFETY: the pid is a thread being traced, which is in ptrace-stop
    // SAFETY: the address points to the pinned state value
    while unsafe { ptrace_peek(pid, state_addr)? } < STATE_READY {
        // SAFETY: the pid is a thread being traced, which is in ptrace-stop
        unsafe {
            ptrace_restart(PTRACE_SYSCALL, pid, &stop)?;
        }
        // SAFETY: the pid is a thread being traced
        unsafe {
            wait_for_stop(pid, &mut stop)?;
        }
    }

    // The thread is stopped at or before the read of the pipe, allow it past that point.
    write_control(control_fd)?;

    // Skip over read of control pipe.
    while stop != StopState::SyscallExit {
        // SAFETY: the pid is a thread being traced, which is in ptrace-stop
        unsafe {
            ptrace_restart(PTRACE_SYSCALL, pid, &stop)?;
        }
        // SAFETY: the pid is a thread being traced
        unsafe {
            wait_for_stop(pid, &mut stop)?;
        }
    }

    // Single step until start of counted region.
    // SAFETY: the pid is a thread being traced, which is in ptrace-stop
    // SAFETY: the address points to the pinned state value
    while unsafe { ptrace_peek(pid, state_addr)? } < STATE_COUNT {
        // SAFETY: the pid is a thread being traced, which is in ptrace-stop
        unsafe {
            ptrace_restart(PTRACE_SINGLESTEP, pid, &stop)?;
        }
        // SAFETY: the pid is a thread being traced
        unsafe {
            wait_for_stop(pid, &mut stop)?;
        }
    }

    // Single step until end of counted region.
    // SAFETY: the pid is a thread being traced, which is in ptrace-stop
    // SAFETY: the address points to the pinned state value
    while unsafe { ptrace_peek(pid, state_addr)? } < STATE_STOP {
        // SAFETY: the pid is a thread being traced, which is in ptrace-stop
        unsafe {
            ptrace_restart(PTRACE_SINGLESTEP, pid, &stop)?;
        }
        if let StopState::SingleStep(addr) = stop {
            write_data(data_fd, addr)?;
        }
        // SAFETY: the pid is a thread being traced
        unsafe {
            wait_for_stop(pid, &mut stop)?;
        }
    }

    // Release the thread.
    // SAFETY: the pid is a thread being traced, which is in ptrace-stop
    unsafe {
        ptrace_restart(PTRACE_DETACH, pid, &stop)?;
    }

    Ok(())
}

unsafe fn ptrace_peek(pid: pid_t, addr: c_ulong) -> Result<c_ulong, c_int> {
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

unsafe fn ptrace_restart(request: c_uint, pid: pid_t, stop: &StopState) -> Result<(), c_int> {
    let request = if request == PTRACE_DETACH {
        PTRACE_DETACH
    } else {
        match stop {
            StopState::SyscallEnter => PTRACE_SYSCALL,
            StopState::Group => PTRACE_LISTEN,
            _ => request,
        }
    };

    let sig = if let StopState::Signal(sig) = *stop {
        sig as c_ulong
    } else {
        0
    };

    // SAFETY: the pid is a thread being traced, which is in ptrace-stop
    // SAFETY: the signal is the one which entered the signal-delivery-stop
    unsafe {
        sys_ptrace(request, pid, 0, sig)?;
    }
    Ok(())
}

#[derive(PartialEq, Eq, Debug)]
enum StopState {
    SyscallEnter,
    SyscallExit,
    Event,
    Group,
    Signal(c_int),
    SingleStep(usize),
    Running,
}

impl StopState {
    unsafe fn update(&mut self, status: c_int, pid: pid_t) -> Result<(), c_int> {
        let sig = WSTOPSIG(status);
        *self = if sig == SIGTRAP | 0x80 {
            if *self == StopState::SyscallEnter {
                StopState::SyscallExit
            } else {
                StopState::SyscallEnter
            }
        } else if sig == SIGTRAP {
            if status >> 16 != 0 {
                StopState::Event
            } else {
                // SAFETY: the target thread is in ptrace-stop
                let siginfo = unsafe { ptrace_getsiginfo(pid)? };
                if siginfo.si_code > 0 {
                    // SAFETY: the stop signal is `SIGTRAP`, which has `si_addr`
                    let addr = unsafe { siginfo.si_addr() };
                    StopState::SingleStep(addr as usize)
                } else {
                    StopState::Signal(sig)
                }
            }
        } else if status >> 16 == PTRACE_EVENT_STOP {
            StopState::Group
        } else {
            StopState::Signal(sig)
        };
        Ok(())
    }
}

unsafe fn wait_for_stop(pid: pid_t, stop: &mut StopState) -> Result<(), c_int> {
    let mut status = 0;
    loop {
        // SAFETY: `waitpid()` is async-signal-safe
        // SAFETY: the pid is a thread being traced; the status pointer is valid
        let ret = unsafe { waitpid(pid, &raw mut status, __WALL) };
        if ret < 0 {
            let err = errno();
            if err != EINTR {
                return Err(err);
            }
        } else if ret == pid {
            break;
        } else {
            return Err(ECHILD);
        }
    }

    if WIFSTOPPED(status) {
        // SAFETY: the pid is a thread being traced, which is in ptrace-stop
        unsafe {
            stop.update(status, pid)?;
        }
        Ok(())
    } else {
        Err(ECHILD)
    }
}

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
