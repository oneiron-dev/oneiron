//! Starting a subprocess with only the descriptors it is meant to have.
//!
//! A descriptor this process opens is not always close-on-exec from the
//! moment it exists. On macOS, std makes a socket pair or a pipe first and
//! marks it close-on-exec in a second call, so a subprocess another thread
//! starts in between keeps a copy across exec: for example the receiving end
//! of a call's socket, and with it the call's key. So every subprocess the
//! server's crates start comes from [`command`] or [`command_with_fds`] (or
//! their tokio forms). Between fork and exec, the process marks every
//! descriptor above the standard three close-on-exec, whatever its flag here,
//! and then puts the descriptors its caller names at the numbers it names. A
//! test in this crate fails on any other `Command::new` in the workspace's
//! crates.

use std::ffi::OsStr;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::os::fd::RawFd;
use std::process::Command;

/// A command for `program` whose process starts with the standard three
/// descriptors and no other.
#[must_use]
pub fn command(program: impl AsRef<OsStr>) -> Command {
    #[cfg(unix)]
    {
        command_with_fds(program, &[])
    }
    #[cfg(not(unix))]
    {
        Command::new(program)
    }
}

/// A command for `program` whose process starts with the standard three
/// descriptors and, for each `(ours, theirs)` in `fds`, this process's
/// descriptor `ours` at number `theirs`, open across exec. No `theirs` may be
/// another pair's `ours`. A closure the caller adds with `pre_exec` runs after
/// this, with the descriptors in place.
#[cfg(unix)]
#[must_use]
pub fn command_with_fds(program: impl AsRef<OsStr>, fds: &[(RawFd, RawFd)]) -> Command {
    use std::os::unix::process::CommandExt as _;
    let mut command = Command::new(program);
    let fds = fds.to_vec();
    let ceiling = descriptor_ceiling();
    // SAFETY: the closure runs in the child between fork and exec. It only
    // makes async-signal-safe calls (close_range, fcntl, dup2) on numbers
    // taken before the fork, takes no lock and allocates nothing.
    unsafe {
        command.pre_exec(move || inherit_only(&fds, ceiling));
    }
    command
}

/// [`command`], for tokio.
#[cfg(feature = "tokio")]
#[must_use]
pub fn tokio_command(program: impl AsRef<OsStr>) -> tokio::process::Command {
    command(program).into()
}

/// [`command_with_fds`], for tokio.
#[cfg(all(unix, feature = "tokio"))]
#[must_use]
pub fn tokio_command_with_fds(
    program: impl AsRef<OsStr>,
    fds: &[(RawFd, RawFd)],
) -> tokio::process::Command {
    command_with_fds(program, fds).into()
}

/// One past the highest descriptor number this process may open, read before
/// the fork.
#[cfg(unix)]
fn descriptor_ceiling() -> RawFd {
    let mut open = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes the struct on the stack.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut open) } == 0 {
        RawFd::try_from(open.rlim_cur.min(65_536)).unwrap_or(1024)
    } else {
        1024
    }
}

/// Marks every descriptor above the standard three, below `ceiling`,
/// close-on-exec, then puts each `(ours, theirs)` in place without the flag.
#[cfg(unix)]
fn inherit_only(fds: &[(RawFd, RawFd)], ceiling: RawFd) -> io::Result<()> {
    close_on_exec_from(3, ceiling);
    for &(ours, theirs) in fds {
        let placed = if ours == theirs {
            // SAFETY: fcntl on a descriptor this process holds; clearing its
            // close-on-exec flag only keeps it across exec.
            unsafe { libc::fcntl(theirs, libc::F_SETFD, 0) == 0 }
        } else {
            // SAFETY: both descriptors are valid in the child; dup2 leaves the
            // copy on `theirs` without close-on-exec.
            unsafe { libc::dup2(ours, theirs) == theirs }
        };
        if !placed {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Marks every descriptor from `first` up close-on-exec, whatever this
/// process had open without the flag: all of them on Linux 5.11 and later,
/// and those below `ceiling` elsewhere.
#[cfg(unix)]
fn close_on_exec_from(first: RawFd, ceiling: RawFd) {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: close_range with CLOSE_RANGE_CLOEXEC only sets a flag on
        // this process's descriptors; it fails on kernels before 5.11, and
        // the loop below covers that.
        let done = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                first,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            )
        } == 0;
        if done {
            return;
        }
    }
    for fd in first..ceiling {
        // SAFETY: fcntl on a descriptor number that may not be open: an
        // unopened one fails with EBADF and is skipped.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags >= 0 && flags & libc::FD_CLOEXEC == 0 {
                libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
    }
}
