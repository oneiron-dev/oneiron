//! Maintenance of the served repositories.
//!
//! The serve path pins automatic maintenance off, so nothing a push starts can
//! outlive its exchange. The host runs it here instead: `git gc --auto`, one
//! repository at a time, under the host's exchange permit and the repository
//! coordinator. Maintenance never turns a push away: it takes the coordinator
//! only when it is free, leaves a repository a writer holds for the next run,
//! and gives the coordinator up, ending its git, as soon as a writer asks for
//! it. `--auto` does work only past git's own thresholds (loose objects, pack
//! count), so a run over a quiet repository costs a directory read.
//!
//! Git reads no system or global configuration here, and runs no hook, signer
//! or daemon. The one command a repository's own configuration can name for
//! gc, `gc.recentObjectsHook`, is a list no later setting clears, so a
//! repository that names one is left unmaintained. A run asked to end is
//! terminated first, which git answers by removing its own lock and temporary
//! files, and the repository is given up only once every git it started is
//! gone.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant, SystemTime};

use crate::git_wire::config::GIT_WIRE_REPO_LOCK_FILE_NAME;
use crate::git_wire::repo::try_lock_repository_for_maintenance;
use crate::origin::smart_http::paths::ORIGIN_REPO_DIR_SUFFIX;
use crate::origin::smart_http::paths::validate_repo_name;
use oneiron_base::error::Result;

/// The longest one repository's maintenance may run before it is killed.
pub const SERVED_REPOSITORY_GC_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// How often a running maintenance checks whether it must stop.
const POLL: Duration = Duration::from_millis(50);

/// How long git has to clean up after a terminate before it is killed, and
/// after a kill before the repository is given up all the same.
const END_GRACE: Duration = Duration::from_secs(5);

/// gc's command named by configuration: a list, run through a shell.
pub const GC_COMMAND_KEY: &str = "gc.recentObjectsHook";

/// Settings pinned on the maintenance command: nothing detaches or outlives
/// it, no daemon starts, no signer runs, and no hook runs.
pub const PINNED: [&str; 9] = [
    "gc.autoDetach=false",
    "maintenance.autoDetach=false",
    "maintenance.auto=false",
    "core.fsmonitor=false",
    "core.hooksPath=/dev/null",
    "gpg.program=false",
    "gpg.ssh.program=false",
    "gpg.x509.program=false",
    "commit.gpgSign=false",
];

/// What one maintenance run over the served repositories did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ServedRepositoryMaintenance {
    /// Served repositories found.
    pub repositories: u64,
    /// Repositories `git gc --auto` ran to completion on.
    pub maintained: u64,
    /// Repositories left for a later run: a writer held the repository or
    /// asked for it, the host had no permit for it, or the run was asked to
    /// stop.
    pub deferred: u64,
    /// Repositories whose maintenance failed or ran past its time.
    pub failed: u64,
    /// Repositories left unmaintained because their own configuration names
    /// a command gc would run.
    pub refused: u64,
}

pub enum Gc {
    Done,
    Stopped,
    Refused,
    Failed,
}

/// How one git run ended.
pub enum Run {
    Exited(std::process::ExitStatus),
    /// `give_way` asked it to end.
    Stopped,
    TimedOut,
}

/// Runs `command` on `repo_dir` as the leader of its own process group, so
/// ending it ends every git it started, for at most
/// [`SERVED_REPOSITORY_GC_TIMEOUT`].
pub fn run(
    mut command: std::process::Command,
    repo_dir: &Path,
    give_way: &impl Fn() -> bool,
) -> Result<Run> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let since = SystemTime::now();
    let mut child = command.spawn()?;
    let deadline = Instant::now() + SERVED_REPOSITORY_GC_TIMEOUT;
    let ended = |child: &mut Child| {
        if end(child) {
            remove_locks_since(repo_dir, since);
        }
    };
    loop {
        if give_way() {
            ended(&mut child);
            return Ok(Run::Stopped);
        }
        if let Some(status) = child.try_wait()? {
            return Ok(Run::Exited(status));
        }
        if Instant::now() >= deadline {
            ended(&mut child);
            return Ok(Run::TimedOut);
        }
        std::thread::sleep(POLL);
    }
}

/// Removes the lock files a killed run left behind: those under `dir` made
/// since `since`. No one else can have made one meanwhile: the run held the
/// repository's coordinator throughout, and every writer takes it. The
/// coordinator's own file is never one of them.
fn remove_locks_since(dir: &Path, since: SystemTime) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            remove_locks_since(&path, since);
        } else if kind.is_file()
            && path.extension().is_some_and(|ext| ext == "lock")
            && entry.file_name() != GIT_WIRE_REPO_LOCK_FILE_NAME
            && entry
                .metadata()
                .and_then(|meta| meta.modified())
                .is_ok_and(|made| made >= since)
        {
            let _ = fs::remove_file(&path);
        }
    }
}

/// Ends the run and every git it started: a terminate first, on which git
/// removes its own lock and temporary files, then a kill for whatever is
/// still there after [`END_GRACE`]. Returns once the leader is reaped and no
/// process of its group is left, or a kill's grace has passed too; `true`
/// when it took a kill, which leaves git no chance to clean up.
fn end(child: &mut Child) -> bool {
    #[cfg(unix)]
    if let Ok(group) = libc::pid_t::try_from(child.id()) {
        for signal in [libc::SIGTERM, libc::SIGKILL] {
            // SAFETY: the group is the child's own, and it is not gone: the
            // leader is unreaped or a member is left, so its id is not reused.
            unsafe {
                libc::kill(-group, signal);
            }
            if group_ended(child, group) {
                return signal == libc::SIGKILL;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    true
}

/// Waits up to [`END_GRACE`] for the leader to be reaped and its process
/// group to be empty.
#[cfg(unix)]
fn group_ended(child: &mut Child, group: libc::pid_t) -> bool {
    let until = Instant::now() + END_GRACE;
    loop {
        if matches!(child.try_wait(), Ok(Some(_))) {
            // SAFETY: signal 0 delivers nothing; it only asks whether any
            // process of the group is left.
            let probe = unsafe { libc::kill(-group, 0) };
            if probe == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return true;
            }
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
