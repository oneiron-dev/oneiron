//! What the host does to an organ process between fork and exec.
//!
//! Built: the socket moves to fd 3 and every other inherited descriptor
//! closes at exec, a clean environment, cwd `/`, its own process group (so
//! a kill reaches what it forks), rlimits (core 0, open files, file size;
//! data on Linux), `no_new_privs` and a new user and network namespace where
//! Linux allows it, nice +10. Not built: filesystem confinement (Landlock,
//! Seatbelt) and a syscall filter, so third-party organs are refused
//! (`Unavailable::ThirdPartyUnconfined`); a descendant that leaves the
//! process group (`setsid`) outlives a kill until that lands. No
//! parent-death signal: Linux ties it to the spawning thread, which may be a
//! short-lived worker; the organ runtime exits at EOF on its socket.

use std::io;
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use crate::spec::OrganSpec;

#[derive(Debug, Clone, Copy)]
struct Plan {
    socket: RawFd,
    memory: u64,
    open_files: u64,
}

/// Configures `command` to start the organ confined.
pub(crate) fn confine(command: &mut Command, socket: RawFd, spec: &OrganSpec) {
    let plan = Plan {
        socket,
        memory: spec.memory_bytes,
        // Per seat: a call's inputs, plus the outputs of the reply before it,
        // which the organ may not have closed yet when the next call lands.
        open_files: 64 + 2 * 16 * u64::from(spec.threads),
    };
    command
        .env_clear()
        .env("ONEIRON_ORGAN_FD", "3")
        .env("LANG", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the closure runs in the child between fork and exec. It only
    // makes async-signal-safe calls (dup2, fcntl, close_range, getrlimit,
    // setpgid, setrlimit, prctl, unshare, setpriority) on values computed
    // before the fork, and allocates nothing.
    unsafe {
        command.pre_exec(move || plan.apply());
    }
}

impl Plan {
    fn apply(self) -> io::Result<()> {
        let moved = if self.socket == 3 {
            // SAFETY: fd 3 is the organ socket, inherited open; clearing its
            // close-on-exec flag only keeps it across exec.
            unsafe { libc::fcntl(3, libc::F_SETFD, 0) == 0 }
        } else {
            // SAFETY: both descriptors are valid in the child; dup2 leaves
            // the copy on fd 3 without close-on-exec.
            unsafe { libc::dup2(self.socket, 3) == 3 }
        };
        if !moved {
            return Err(io::Error::last_os_error());
        }
        close_on_exec_above(3);
        // SAFETY: setpgid on this process only: it leads a new group, so the
        // host's group kill reaches every process it forks.
        if unsafe { libc::setpgid(0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        limit(libc::RLIMIT_CORE, 0)?;
        limit(libc::RLIMIT_NOFILE, self.open_files)?;
        limit(libc::RLIMIT_FSIZE, self.memory)?;
        #[cfg(target_os = "linux")]
        linux(self.memory)?;
        // SAFETY: setpriority on this process only; a failure leaves the
        // default priority and is not fatal.
        unsafe {
            libc::setpriority(libc::PRIO_PROCESS, 0, 10);
        }
        Ok(())
    }
}

/// Marks every descriptor above `keep` close-on-exec, so the organ starts
/// with its socket and the standard three only, whatever the host process
/// had open without the flag.
fn close_on_exec_above(keep: u32) {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: close_range with CLOSE_RANGE_CLOEXEC only sets a flag on
        // this process's descriptors; it fails on kernels before 5.11, and
        // the loop below covers that.
        let done = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                keep + 1,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            )
        } == 0;
        if done {
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
    let ceiling = i32::try_from(ceiling).unwrap_or(1024);
    let first = i32::try_from(keep).unwrap_or(i32::MAX).saturating_add(1);
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

#[cfg(target_os = "linux")]
fn linux(memory: u64) -> io::Result<()> {
    limit(libc::RLIMIT_DATA, memory)?;
    // SAFETY: prctl with constant arguments on this process.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: unshare on this single-threaded child. Hosts that forbid
    // unprivileged user namespaces refuse it; the organ then shares the
    // network, and `net_isolated` reports that.
    unsafe {
        libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
type Resource = libc::__rlimit_resource_t;
#[cfg(not(target_os = "linux"))]
type Resource = libc::c_int;

fn limit(resource: Resource, value: u64) -> io::Result<()> {
    let value = libc::rlim_t::try_from(value).unwrap_or(libc::RLIM_INFINITY);
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: setrlimit reads a fully initialized struct on the stack.
    if unsafe { libc::setrlimit(resource, &limit) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Whether the organ runs in its own network namespace (Linux only).
pub(crate) fn net_isolated(pid: u32) -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    let theirs = std::fs::read_link(format!("/proc/{pid}/ns/net"));
    let ours = std::fs::read_link("/proc/self/ns/net");
    matches!((theirs, ours), (Ok(theirs), Ok(ours)) if theirs != ours)
}
