//! Maintenance of the served repositories.
//!
//! The serve path pins automatic maintenance off, so nothing a push starts can
//! outlive its exchange. The host runs it here instead: `git gc --auto`, one
//! repository at a time, as an exchange would, under the host's exchange
//! permit and the repository coordinator, and never waiting for either. A
//! repository a push holds is left for the next run. `--auto` does work only
//! past git's own thresholds (loose objects, pack count), so a run over a
//! quiet repository costs a directory read.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use super::paths::{ORIGIN_REPO_DIR_SUFFIX, origin_serving_root, validate_repo_name};
use super::serve::repo_common_dir;
use super::serve_cmd::path_arg;
use crate::Vault;
use crate::error::Result;
use crate::git_wire::{GitWireProcessEnv, try_lock_repository};

/// The longest one repository's maintenance may run before it is killed.
pub const SERVED_REPOSITORY_GC_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// How often a running maintenance checks whether it must stop.
const POLL: Duration = Duration::from_millis(50);

/// Settings pinned on the maintenance command: nothing detaches or outlives
/// it, no daemon starts, no signer runs, and no hook runs.
const PINNED: [&str; 9] = [
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
    /// Repositories left for a later run: a push held the repository, no
    /// exchange permit was free, or the run was asked to stop.
    pub deferred: u64,
    /// Repositories whose maintenance failed or ran past its time.
    pub failed: u64,
}

/// Runs `git gc --auto` on every served repository. `admit` takes the host's
/// exchange permit for one repository, held until its maintenance ends, or
/// returns `None` when none is free. `stop` asks the run to start no further
/// repository and to end the one in flight.
pub fn maintain_served_repositories(
    vault: &Vault,
    mut admit: impl FnMut() -> Option<Box<dyn Send>>,
    stop: impl Fn() -> bool,
) -> Result<ServedRepositoryMaintenance> {
    let repositories = served_repositories(vault)?;
    let mut report = ServedRepositoryMaintenance {
        repositories: u64::try_from(repositories.len()).unwrap_or(u64::MAX),
        ..ServedRepositoryMaintenance::default()
    };
    for repo_dir in repositories {
        if stop() {
            report.deferred += 1;
            continue;
        }
        let Some(_permit) = admit() else {
            report.deferred += 1;
            continue;
        };
        let Ok(common_dir) = repo_common_dir(&repo_dir) else {
            report.failed += 1;
            continue;
        };
        let Some(_coordinator) = try_lock_repository(&common_dir)? else {
            report.deferred += 1;
            continue;
        };
        match collect_garbage(&repo_dir, &stop) {
            Ok(Gc::Done) => report.maintained += 1,
            Ok(Gc::Stopped) => report.deferred += 1,
            Ok(Gc::Failed) | Err(_) => report.failed += 1,
        }
    }
    Ok(report)
}

/// Every served repository: the directories of the serving root named as a
/// repository is, in name order.
fn served_repositories(vault: &Vault) -> Result<Vec<PathBuf>> {
    let root = origin_serving_root(vault)?;
    let mut repositories = Vec::new();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(repo_name) = name
            .to_str()
            .and_then(|name| name.strip_suffix(ORIGIN_REPO_DIR_SUFFIX))
        else {
            continue;
        };
        if validate_repo_name(repo_name).is_ok() && entry.file_type()?.is_dir() {
            repositories.push(entry.path());
        }
    }
    repositories.sort();
    Ok(repositories)
}

enum Gc {
    Done,
    Stopped,
    Failed,
}

/// Runs `git gc --auto --quiet` in `repo_dir` with a closed environment, as the
/// leader of its own process group, so a kill ends every git it started.
fn collect_garbage(repo_dir: &Path, stop: &impl Fn() -> bool) -> Result<Gc> {
    let process_env = GitWireProcessEnv::capture()?;
    let mut command = oneiron_spawn::command(process_env.git_binary().as_os_str());
    for pinned in PINNED {
        command.arg("-c").arg(pinned);
    }
    command
        .args(["gc", "--auto", "--quiet"])
        .env_clear()
        .env("GIT_DIR", path_arg(repo_dir)?)
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    let deadline = Instant::now() + SERVED_REPOSITORY_GC_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(if status.success() {
                Gc::Done
            } else {
                Gc::Failed
            });
        }
        if stop() {
            end(&mut child);
            return Ok(Gc::Stopped);
        }
        if Instant::now() >= deadline {
            end(&mut child);
            return Ok(Gc::Failed);
        }
        std::thread::sleep(POLL);
    }
}

/// Kills the maintenance and every git it started, and reaps it.
fn end(child: &mut Child) {
    #[cfg(unix)]
    if let Ok(group) = libc::pid_t::try_from(child.id()) {
        // SAFETY: the child was spawned as leader of its own process group
        // and is not reaped yet, so the group id is still its.
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}
