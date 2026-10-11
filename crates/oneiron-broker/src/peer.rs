//! Who this process is, and closing its memory to processes of its own uid.

use std::io;

/// The uid this process runs as.
pub(crate) fn own_uid() -> u32 {
    // SAFETY: getuid takes no arguments, cannot fail and touches no memory.
    unsafe { libc::getuid() }
}

/// The pid of the process that started this one.
pub(crate) fn parent_pid() -> u32 {
    // SAFETY: getppid takes no arguments, cannot fail and touches no memory.
    let pid = unsafe { libc::getppid() };
    u32::try_from(pid).unwrap_or(0)
}

/// Makes this process non-dumpable, so no other process of its uid can ptrace
/// it or read its `/proc/<pid>/{mem,environ}`.
#[cfg(target_os = "linux")]
pub(crate) fn harden() -> io::Result<()> {
    // SAFETY: prctl with constant arguments on this process.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Denies debugger attach to this process.
#[cfg(target_os = "macos")]
pub(crate) fn harden() -> io::Result<()> {
    // SAFETY: PT_DENY_ATTACH acts on this process only and reads nothing
    // through its null address.
    if unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// No way to close this process's memory is known here, so the broker does
/// not start.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn harden() -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

/// Confines the same-user child, as the organ host confines an organ, before
/// it reads anything. It closes its memory first. It then refuses to run
/// under a tracer that attached before that, and closes every descriptor it
/// inherited beside the standard three. It sets no core file and, on Linux,
/// no new privileges.
///
/// It takes no user or network namespace, as an organ does. It sends to the
/// provider, so it needs the network. And a user namespace the daemon's uid
/// owns would give that uid the ptrace power back over it.
pub(crate) fn confine_child() -> io::Result<()> {
    harden()?;
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status")?;
        let traced = status
            .lines()
            .find_map(|line| line.strip_prefix("TracerPid:"))
            .is_none_or(|pid| pid.trim() != "0");
        if traced {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "a tracer is attached",
            ));
        }
        // SAFETY: prctl with constant arguments on this process.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads a fully initialized struct on the stack.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) } != 0 {
        return Err(io::Error::last_os_error());
    }
    close_inherited();
    Ok(())
}

/// Closes every descriptor above the standard three. This runs first in the
/// child, before it has opened anything of its own.
fn close_inherited() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: close_range closes this process's descriptors from 3 up;
        // nothing of this process holds one yet. It fails on kernels before
        // 5.9, and the loop below covers that.
        if unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) } == 0 {
            return;
        }
    }
    let mut open = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes the struct on the stack.
    let ceiling = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut open) } == 0 {
        open.rlim_cur.min(65_536)
    } else {
        1024
    };
    for fd in 3..i32::try_from(ceiling).unwrap_or(1024) {
        // SAFETY: close on a descriptor number that may not be open: an
        // unopened one fails with EBADF and is skipped.
        unsafe {
            libc::close(fd);
        }
    }
}
