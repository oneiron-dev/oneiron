//! Who this process is, and closing its memory to processes of its own uid.

use std::io;
use std::os::fd::{FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

/// The descriptor a same-user child inherits its channel to the daemon on.
pub(crate) const CHANNEL_FD: RawFd = 3;

/// The uid this process runs as.
pub(crate) fn own_uid() -> u32 {
    // SAFETY: getuid takes no arguments, cannot fail and touches no memory.
    unsafe { libc::getuid() }
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
/// inherited beside the standard three and its channel on [`CHANNEL_FD`]. It
/// sets no core file and, on Linux, no new privileges.
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

/// Closes every descriptor above [`CHANNEL_FD`]. This runs first in the
/// child, before it has opened anything of its own.
fn close_inherited() {
    let first = CHANNEL_FD + 1;
    #[cfg(target_os = "linux")]
    {
        // SAFETY: close_range closes this process's descriptors from `first`
        // up; nothing of this process holds one yet. It fails on kernels
        // before 5.9, and the loop below covers that.
        if unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, 0_u32) } == 0 {
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
    for fd in first..i32::try_from(ceiling).unwrap_or(1024) {
        // SAFETY: close on a descriptor number that may not be open: an
        // unopened one fails with EBADF and is skipped.
        unsafe {
            libc::close(fd);
        }
    }
}

/// The channel the daemon put on [`CHANNEL_FD`], once that is an open Unix
/// socket. Taken once, after [`confine_child`] closed every other inherited
/// descriptor.
pub(crate) fn inherited_channel() -> io::Result<UnixStream> {
    // SAFETY: F_GETFD only reads a descriptor number's flags; one that is not
    // open fails with EBADF.
    if unsafe { libc::fcntl(CHANNEL_FD, libc::F_GETFD) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CHANNEL_FD is open, and nothing else in this process owns it:
    // confine_child closed every inherited descriptor but it, and the process
    // has opened nothing of its own since.
    let channel = unsafe { OwnedFd::from_raw_fd(CHANNEL_FD) };
    if rustix::net::getsockname(&channel)?.address_family() != rustix::net::AddressFamily::UNIX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a Unix socket",
        ));
    }
    Ok(UnixStream::from(channel))
}
