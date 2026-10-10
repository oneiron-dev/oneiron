//! What the host does to an organ process between fork and exec.
//!
//! Built: the socket moves to fd 3, a clean environment, cwd `/`, rlimits
//! (core 0, open files, file size; data on Linux), `no_new_privs` and a new
//! user and network namespace where Linux allows it, nice +10. Not built:
//! filesystem confinement (Landlock, Seatbelt) and a syscall filter, so
//! third-party organs are refused (`Unavailable::ThirdPartyUnconfined`).
//! No parent-death signal: Linux ties it to the spawning thread, which may
//! be a short-lived worker; the organ runtime exits at EOF on its socket.

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
        open_files: 64 + 16 * u64::from(spec.threads),
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
    // makes async-signal-safe calls (dup2, fcntl, setrlimit, prctl, unshare,
    // setpriority) on values computed before the fork, and allocates nothing.
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
