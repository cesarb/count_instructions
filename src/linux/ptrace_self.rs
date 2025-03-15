// Code in this file should be treated as #![no_std]; it should only use core and libc.

use super::Address;
use libc::*;

pub const STATE_INIT: c_ulong = 0;
pub const STATE_READY: c_ulong = 1;
pub const STATE_COUNT: c_ulong = 2;
pub const STATE_STOP: c_ulong = 3;

pub struct TraceToken;

#[inline]
unsafe fn errno() -> c_int {
    *__errno_location()
}

unsafe fn sys_ptrace(
    request: c_uint,
    pid: pid_t,
    addr: c_ulong,
    data: c_ulong,
) -> Result<c_long, c_int> {
    let ret = syscall(SYS_ptrace, request as c_long, pid as c_long, addr, data);
    if ret < 0 { Err(errno()) } else { Ok(ret) }
}

// SAFETY: this runs in a forked child of a multithreaded program, so only
// async-signal-safe functions from libc or raw system calls can be used here.
pub unsafe fn trace(
    pid: pid_t,
    state_addr: c_ulong,
    control_fd: c_int,
    data_fd: c_int,
    ready_fd: c_int,
    _token: &mut TraceToken,
) -> Result<(), c_int> {
    wait_for_set_ptracer(ready_fd)?;
    close(ready_fd);

    sys_ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESYSGOOD as c_ulong)?;
    sys_ptrace(PTRACE_INTERRUPT, pid, 0, 0)?;

    // Tell the helper thread that the target thread has been attached.
    write_data(data_fd, 0)?;

    let mut stop = StopState::Running;
    wait_for_stop(pid, &mut stop)?;

    // Fast skip until ready.
    while ptrace_peek(pid, state_addr)? < STATE_READY {
        ptrace_restart(PTRACE_SYSCALL, pid, &stop)?;
        wait_for_stop(pid, &mut stop)?;
    }

    // The thread is stopped at or before the read of the pipe, allow it past that point.
    write_control(control_fd)?;
    close(control_fd);

    // Skip over read of control pipe.
    while stop != StopState::SyscallExit {
        ptrace_restart(PTRACE_SYSCALL, pid, &stop)?;
        wait_for_stop(pid, &mut stop)?;
    }

    // Single step until start of counted region.
    while ptrace_peek(pid, state_addr)? < STATE_COUNT {
        ptrace_restart(PTRACE_SINGLESTEP, pid, &stop)?;
        wait_for_stop(pid, &mut stop)?;
    }

    // Single step until end of counted region.
    while ptrace_peek(pid, state_addr)? < STATE_STOP {
        ptrace_restart(PTRACE_SINGLESTEP, pid, &stop)?;
        if let StopState::SingleStep(addr) = stop {
            write_data(data_fd, addr)?;
        }
        wait_for_stop(pid, &mut stop)?;
    }

    // Release the thread.
    ptrace_restart(PTRACE_DETACH, pid, &stop)?;

    Ok(())
}

unsafe fn ptrace_peek(pid: pid_t, addr: c_ulong) -> Result<c_ulong, c_int> {
    let mut data = 0;
    sys_ptrace(PTRACE_PEEKDATA, pid, addr, &mut data as *mut _ as c_ulong)?;
    Ok(data)
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

    sys_ptrace(request, pid, 0, sig)?;
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
                let mut siginfo: siginfo_t = core::mem::zeroed();
                sys_ptrace(PTRACE_GETSIGINFO, pid, 0, &mut siginfo as *mut _ as c_ulong)?;
                if siginfo.si_code > 0 {
                    StopState::SingleStep(siginfo.si_addr() as usize)
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
        let ret = waitpid(pid, &mut status, __WALL);
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
        stop.update(status, pid)?;
        Ok(())
    } else {
        Err(ECHILD)
    }
}

unsafe fn retry_pipe_on_intr<F>(mut f: F, len: usize) -> Result<(), c_int>
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
        } else if ret == len as ssize_t {
            break Ok(());
        } else {
            break Err(EPIPE);
        }
    }
}

unsafe fn wait_for_set_ptracer(ready_fd: c_int) -> Result<(), c_int> {
    let mut buf: [u8; 1] = [0];
    let len = buf.len();
    retry_pipe_on_intr(
        || read(ready_fd, &mut buf as *mut [u8] as *mut c_void, len),
        len,
    )
}

unsafe fn write_control(control_fd: c_int) -> Result<(), c_int> {
    let buf: [u8; 1] = [0];
    let len = buf.len();
    retry_pipe_on_intr(
        || write(control_fd, &buf as *const [u8] as *const c_void, len),
        len,
    )
}

unsafe fn write_data(data_fd: c_int, address: Address) -> Result<(), c_int> {
    let buf = address.to_ne_bytes();
    let len = buf.len();
    retry_pipe_on_intr(
        || write(data_fd, &buf as *const [u8] as *const c_void, len),
        len,
    )
}
