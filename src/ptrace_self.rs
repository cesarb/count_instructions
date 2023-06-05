// Code in this file should be treated as #![no_std]; it should only use core and libc.

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
    if ret < 0 {
        Err(errno())
    } else {
        Ok(ret)
    }
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

    let mut status = wait_for_stop(pid)?;

    // Fast skip until ready.
    while ptrace_peek(pid, state_addr)? < STATE_READY {
        ptrace_restart(PTRACE_SYSCALL, pid, status)?;
        status = wait_for_stop(pid)?;
    }

    // The thread is stopped at or before the read of the pipe, allow it past that point.
    write_control(control_fd)?;
    close(control_fd);

    // Wait for syscall-stop (read of control pipe).
    while WSTOPSIG(status) != SIGTRAP | 0x80 {
        ptrace_restart(PTRACE_SYSCALL, pid, status)?;
        status = wait_for_stop(pid)?;
    }

    // Single step until start of counted region.
    while ptrace_peek(pid, state_addr)? < STATE_COUNT {
        ptrace_restart(PTRACE_SINGLESTEP, pid, status)?;
        status = wait_for_stop(pid)?;
        if ptrace_sigtrap_addr(pid, status)?.is_some() {
            status = 0;
        }
    }

    // Single step until end of counted region.
    while ptrace_peek(pid, state_addr)? < STATE_STOP {
        ptrace_restart(PTRACE_SINGLESTEP, pid, status)?;
        status = wait_for_stop(pid)?;
        if let Some(addr) = ptrace_sigtrap_addr(pid, status)? {
            status = 0;
            write_data(data_fd, addr)?;
        }
    }

    // Release the thread.
    ptrace_restart(PTRACE_DETACH, pid, status)?;

    Ok(())
}

unsafe fn ptrace_peek(pid: pid_t, addr: c_ulong) -> Result<c_ulong, c_int> {
    let mut data = 0;
    sys_ptrace(PTRACE_PEEKDATA, pid, addr, &mut data as *mut _ as c_ulong)?;
    Ok(data)
}

unsafe fn ptrace_sigtrap_addr(pid: pid_t, status: c_int) -> Result<Option<c_ulong>, c_int> {
    if WSTOPSIG(status) == SIGTRAP && status >> 16 == 0 {
        let mut siginfo: siginfo_t = core::mem::zeroed();
        sys_ptrace(PTRACE_GETSIGINFO, pid, 0, &mut siginfo as *mut _ as c_ulong)?;
        if siginfo.si_code > 0 {
            return Ok(Some(siginfo.si_addr() as c_ulong));
        }
    }

    Ok(None)
}

#[allow(clippy::if_same_then_else)]
unsafe fn ptrace_restart(request: c_uint, pid: pid_t, status: c_int) -> Result<c_long, c_int> {
    let sig = WSTOPSIG(status);
    if status == 0 {
        // single-step SIGTRAP
        sys_ptrace(request, pid, 0, 0)
    } else if sig == SIGTRAP | 0x80 {
        // syscall-stop
        sys_ptrace(request, pid, 0, 0)
    } else if sig == SIGTRAP && status >> 16 != 0 {
        // ptrace-event-stop
        sys_ptrace(request, pid, 0, 0)
    } else if status >> 16 == PTRACE_EVENT_STOP {
        // group-stop
        let request = if request == PTRACE_DETACH {
            PTRACE_DETACH
        } else {
            PTRACE_LISTEN
        };
        sys_ptrace(request, pid, 0, 0)
    } else {
        // signal-delivery-stop
        sys_ptrace(request, pid, 0, sig as c_ulong)
    }
}

unsafe fn wait_for_stop(pid: pid_t) -> Result<c_int, c_int> {
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
        Ok(status)
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

unsafe fn write_data(data_fd: c_int, address: c_ulong) -> Result<(), c_int> {
    let buf = address.to_ne_bytes();
    let len = buf.len();
    retry_pipe_on_intr(
        || write(data_fd, &buf as *const [u8] as *const c_void, len),
        len,
    )
}
