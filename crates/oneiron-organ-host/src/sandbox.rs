//! What the host does to an organ process between fork and exec.
//!
//! Built: the socket moves to fd 3 and every other inherited descriptor
//! closes at exec (`oneiron_spawn::command_with_fds`, which the caller starts
//! the organ through), a clean environment, cwd `/`, its own process group (so
//! a kill reaches what it forks), rlimits (core 0, open files, file size;
//! data on Linux), `no_new_privs` and a new user and network namespace where
//! Linux allows it, nice +10. Not built: filesystem confinement (Landlock,
//! Seatbelt) and a syscall filter, so third-party organs are refused
//! (`Unavailable::ThirdPartyUnconfined`); a descendant that leaves the
//! process group (`setsid`) outlives a kill until that lands. No
//! parent-death signal: Linux ties it to the spawning thread, which may be a
//! short-lived worker; the organ runtime exits at EOF on its socket.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use crate::spec::OrganSpec;

#[derive(Debug, Clone, Copy)]
struct Plan {
    memory: u64,
    open_files: u64,
}

/// Configures `command`, made by `oneiron_spawn::command_with_fds` with the
/// organ socket on fd 3, to start the organ confined.
pub(crate) fn confine(command: &mut Command, spec: &OrganSpec) {
    let plan = Plan {
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
    // SAFETY: the closure runs in the child between fork and exec, after the
    // descriptors are in place. It only makes async-signal-safe calls
    // (setpgid, setrlimit, prctl, unshare, setpriority) on values computed
    // before the fork, and allocates nothing.
    unsafe {
        command.pre_exec(move || plan.apply());
    }
}

impl Plan {
    fn apply(self) -> io::Result<()> {
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
