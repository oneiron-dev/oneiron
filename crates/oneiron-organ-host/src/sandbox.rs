//! What the host does to an organ process between fork and exec.
//!
//! Built: the socket moves to fd 3 and every other inherited descriptor
//! closes at exec (`oneiron_spawn::command_with_fds`, which the caller starts
//! the organ through), a clean environment, cwd `/`, its own process group (so
//! a kill reaches what it forks), rlimits (core 0, open files, file size;
//! data on Linux), `no_new_privs` and a new user and network namespace where
//! Linux allows it, nice +10. Not built: a syscall filter. No parent-death
//! signal: Linux ties it to the spawning thread, which may be a short-lived
//! worker; the organ runtime exits at EOF on its socket.
//!
//! A third-party organ also starts inside a filesystem fence (FIX 7885,
//! ARCH-0075): it reads the system's own files, its program and its spec's
//! read dirs, writes its write dirs and the system's temp dir, and touches
//! nothing else. On Linux the fence is Landlock (ABI 3 or later): the
//! ruleset is built before the fork, and the child restricts itself to it
//! beside `no_new_privs`. On macOS the organ starts through Seatbelt's
//! `sandbox-exec` (`seatbelt`). A fence that does not apply fails the start,
//! so the organ never runs unfenced; a host with no fence refuses
//! third-party organs (`Unavailable::ThirdPartyUnconfined`,
//! [`filesystem_confined`]).
//!
//! A first-party organ's data and file-size limits start at its memory
//! grant and grow with what its own buffers are granted (`memory.grow`):
//! their soft limits move, under no hard one (FIX 6194). On Linux the host
//! moves them as it grants; elsewhere it cannot move another process's
//! limits, so the file-size cutoff is lifted and the machine's floor alone
//! holds those bytes. A third-party organ's limits are hard at its grant.
//!
//! What a start isolated the organ with is a typed fact on its status
//! ([`OrganIsolation`]), and on each call's receipt (FIX 10582): whether
//! the kernel made its namespaces, and what fences its descendants. Neither
//! refuses a start (FIX 7886): where a host forbids user namespaces, or has
//! no cgroup to fence descendants in, the organ runs, and the fact says so. A descendant fence is a cgroup of the
//! organ's own (`fence`): every process it starts, one that leaves its
//! process group with `setsid` included, ends with it (FIX 7887).

use std::ffi::OsString;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use crate::isolation::{DescendantFence, NamespaceFact, OrganIsolation};
use crate::spec::{OrganSpec, OrganTier};

mod fence;
#[cfg(target_os = "macos")]
mod seatbelt;

pub(crate) use fence::Cell;

/// Limits as the kernel takes them, worked out before the fork.
#[derive(Debug)]
struct Plan {
    /// The soft data limit.
    #[cfg(target_os = "linux")]
    data: libc::rlim_t,
    /// The soft file-size limit.
    file_size: libc::rlim_t,
    /// The hard data and file-size limits.
    hard: libc::rlim_t,
    open_files: libc::rlim_t,
    /// Where the child writes its outcomes, before exec.
    #[cfg(target_os = "linux")]
    status: Option<i32>,
    /// The `cgroup.procs` of the organ's cell, which the child joins first.
    join: Option<std::ffi::CString>,
    /// A third-party organ's Landlock ruleset, which the child restricts
    /// itself to before exec (FIX 7885).
    #[cfg(target_os = "linux")]
    landlock: Option<std::os::fd::OwnedFd>,
}

/// What [`confine`] set up that the start reads back once the child runs.
pub(crate) struct Confined {
    /// The pipe the child writes its outcomes to: read once it has exec'd.
    #[cfg(target_os = "linux")]
    status: Option<(io::PipeReader, io::PipeWriter)>,
    cell: Result<Cell, String>,
}

/// Configures `command`, made by `oneiron_spawn::command_with_fds` with the
/// organ socket on fd 3, to start the organ confined.
///
/// # Errors
/// The pipe the child reports its isolation on could not be made, or a
/// third-party organ's filesystem fence could not be built.
pub(crate) fn confine(command: &mut Command, spec: &OrganSpec) -> io::Result<Confined> {
    let grant = rlim(Some(spec.memory_bytes));
    let first_party = spec.tier == OrganTier::FirstParty;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    if !first_party {
        return Err(io::Error::other(
            "this platform has no filesystem fence for a third-party organ",
        ));
    }
    let cell = fence::cell();
    #[cfg(target_os = "linux")]
    let status = Some(io::pipe()?);
    #[cfg(target_os = "linux")]
    let landlock = if first_party {
        None
    } else {
        Some(landlock_ruleset(spec)?)
    };
    let plan = Plan {
        #[cfg(target_os = "linux")]
        data: grant,
        // Elsewhere nothing can raise it while the organ runs: lifted.
        file_size: if first_party && !cfg!(target_os = "linux") {
            libc::RLIM_INFINITY
        } else {
            grant
        },
        hard: if first_party {
            libc::RLIM_INFINITY
        } else {
            grant
        },
        // Per seat: a call's inputs, plus the outputs of the reply before it,
        // which the organ may not have closed yet when the next call lands.
        open_files: rlim(Some(64 + 2 * 16 * u64::from(spec.threads))),
        #[cfg(target_os = "linux")]
        status: status
            .as_ref()
            .map(|(_, writer)| std::os::fd::AsRawFd::as_raw_fd(writer)),
        join: cell.as_ref().ok().map(|cell| cell.procs().to_owned()),
        #[cfg(target_os = "linux")]
        landlock,
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
    // (open, write, close, setpgid, setrlimit, prctl, landlock_restrict_self,
    // unshare, setpriority) on values computed before the fork, and
    // allocates nothing.
    unsafe {
        command.pre_exec(move || plan.apply());
    }
    Ok(Confined {
        #[cfg(target_os = "linux")]
        status,
        cell,
    })
}

/// A byte count as the kernel's limit: none past what it can say.
fn rlim(value: Option<u64>) -> libc::rlim_t {
    value
        .and_then(|value| libc::rlim_t::try_from(value).ok())
        .unwrap_or(libc::RLIM_INFINITY)
}

/// The program and arguments that start `spec`'s organ: a third-party organ
/// on macOS starts through Seatbelt (`seatbelt`), every other as it is.
pub(crate) fn argv(spec: &OrganSpec) -> (PathBuf, Vec<OsString>) {
    #[cfg(target_os = "macos")]
    if spec.tier == OrganTier::ThirdParty {
        return seatbelt::argv(spec);
    }
    (spec.program.clone(), spec.args.clone())
}

/// Whether this host can fence a third-party organ's filesystem (FIX
/// 7885): Landlock ABI 3 or later on Linux, Seatbelt's `sandbox-exec` on
/// macOS. Where it cannot, the host refuses third-party organs.
#[must_use]
pub fn filesystem_confined() -> bool {
    static CONFINED: OnceLock<bool> = OnceLock::new();
    *CONFINED.get_or_init(fence_available)
}

#[cfg(target_os = "linux")]
fn fence_available() -> bool {
    oneiron_container::landlock_abi() >= 3
}

#[cfg(target_os = "macos")]
fn fence_available() -> bool {
    std::path::Path::new(seatbelt::SANDBOX_EXEC).is_file()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn fence_available() -> bool {
    false
}

/// A third-party organ's Landlock ruleset (FIX 7885): its program and read
/// dirs read-only and its write dirs read-write, beside the system set.
#[cfg(target_os = "linux")]
fn landlock_ruleset(spec: &OrganSpec) -> io::Result<std::os::fd::OwnedFd> {
    let mut read = vec![spec.program.as_path()];
    read.extend(spec.read_dirs.iter().map(PathBuf::as_path));
    oneiron_container::landlock_ruleset(&read, &spec.write_dirs)
}

impl Plan {
    fn apply(&self) -> io::Result<()> {
        // The cell first, while the child has the engine's own credentials
        // and has started nothing: whatever it starts is in it.
        let joined = self.join.as_ref().map_or(-1, |procs| fence::join(procs));
        // SAFETY: setpgid on this process only: it leads a new group, so the
        // host's group kill reaches every process it forks.
        if unsafe { libc::setpgid(0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        limit(libc::RLIMIT_CORE, 0, 0)?;
        limit(libc::RLIMIT_NOFILE, self.open_files, self.open_files)?;
        limit(libc::RLIMIT_FSIZE, self.file_size, self.hard)?;
        #[cfg(target_os = "linux")]
        self.linux(joined)?;
        #[cfg(not(target_os = "linux"))]
        let _ = joined;
        // SAFETY: setpriority on this process only; a failure leaves the
        // default priority and is not fatal.
        unsafe {
            libc::setpriority(libc::PRIO_PROCESS, 0, 10);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn linux(&self, joined: i32) -> io::Result<()> {
        limit(libc::RLIMIT_DATA, self.data, self.hard)?;
        // SAFETY: prctl with constant arguments on this process.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // A third-party organ's filesystem fence: an error fails the start,
        // so the organ never runs unfenced (FIX 7885).
        if let Some(ruleset) = &self.landlock {
            oneiron_container::landlock_restrict(std::os::fd::AsFd::as_fd(ruleset))?;
        }
        // SAFETY: unshare on this single-threaded child. Hosts that forbid
        // unprivileged user namespaces refuse it; the organ then shares the
        // network, and its isolation fact says so.
        let unshared = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) };
        let namespaces = if unshared == 0 { 0 } else { errno() };
        if let Some(fd) = self.status {
            let mut word = [0u8; 8];
            word[..4].copy_from_slice(&namespaces.to_ne_bytes());
            word[4..].copy_from_slice(&joined.to_ne_bytes());
            // SAFETY: write(2) of a buffer on this stack to the status pipe,
            // open in this child until exec closes it.
            unsafe {
                libc::write(fd, word.as_ptr().cast(), word.len());
            }
        }
        Ok(())
    }
}

/// The calling thread's errno.
#[cfg(target_os = "linux")]
fn errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

impl Confined {
    /// What the start isolated the organ with, once the child has exec'd,
    /// and the cell it is fenced in, if it joined one.
    pub(crate) fn started(self) -> (OrganIsolation, Option<Cell>) {
        #[cfg(target_os = "linux")]
        let (namespaces, joined) = match self.status {
            Some((mut reader, writer)) => {
                drop(writer);
                let mut word = [0u8; 8];
                match io::Read::read_exact(&mut reader, &mut word) {
                    Ok(()) => {
                        let at = |from: usize| {
                            i32::from_ne_bytes([
                                word[from],
                                word[from + 1],
                                word[from + 2],
                                word[from + 3],
                            ])
                        };
                        let namespaces = match at(0) {
                            0 => NamespaceFact::Isolated,
                            errno => NamespaceFact::Refused { errno },
                        };
                        (namespaces, Some(at(4)))
                    }
                    Err(_) => (NamespaceFact::Unobserved, None),
                }
            }
            None => (NamespaceFact::Unobserved, None),
        };
        #[cfg(not(target_os = "linux"))]
        let (namespaces, joined) = (NamespaceFact::NotOnPlatform, None::<i32>);
        let (descendants, cell) = match (self.cell, joined) {
            (Ok(cell), Some(0)) => (DescendantFence::Cgroup, Some(cell)),
            (Ok(_), Some(errno)) => (
                DescendantFence::ProcessGroup {
                    why: format!("the organ could not join its cgroup (errno {errno})"),
                },
                None,
            ),
            (Ok(_), None) => (
                DescendantFence::ProcessGroup {
                    why: "the organ's cgroup join was not observed".to_owned(),
                },
                None,
            ),
            (Err(why), _) => (DescendantFence::ProcessGroup { why }, None),
        };
        let isolation = OrganIsolation {
            namespaces,
            descendants,
        };
        (isolation, cell)
    }
}

#[cfg(target_os = "linux")]
type Resource = libc::__rlimit_resource_t;
#[cfg(not(target_os = "linux"))]
type Resource = libc::c_int;

fn limit(resource: Resource, soft: libc::rlim_t, hard: libc::rlim_t) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
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
