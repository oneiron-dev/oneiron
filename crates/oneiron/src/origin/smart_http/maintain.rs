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
use std::time::{Duration, Instant};

use super::paths::{ORIGIN_REPO_DIR_SUFFIX, origin_serving_root, validate_repo_name};
use super::serve::repo_common_dir;
use super::serve_cmd::path_arg;
use crate::Vault;
use crate::error::Result;
use crate::git_wire::{GitWireProcessEnv, try_lock_repository_for_maintenance};

/// The longest one repository's maintenance may run before it is killed.
pub const SERVED_REPOSITORY_GC_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// How often a running maintenance checks whether it must stop.
const POLL: Duration = Duration::from_millis(50);

/// How long git has to clean up after a terminate before it is killed, and
/// after a kill before the repository is given up all the same.
const END_GRACE: Duration = Duration::from_secs(5);

/// gc's command named by configuration: a list, run through a shell.
const GC_COMMAND_KEY: &str = "gc.recentObjectsHook";

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

/// Runs `git gc --auto` on every served repository. `admit` takes the host's
/// hold for one repository, its exchange permit, kept until that
/// repository's maintenance ends, or returns `None` when the host has none
/// to give. `stop` asks the run to start no further repository and to end
/// the one in flight.
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
        let Some(coordinator) = try_lock_repository_for_maintenance(&common_dir)? else {
            report.deferred += 1;
            continue;
        };
        match collect_garbage(&repo_dir, || stop() || coordinator.asked_to_give_way()) {
            Ok(Gc::Done) => report.maintained += 1,
            Ok(Gc::Stopped) => report.deferred += 1,
            Ok(Gc::Refused) => report.refused += 1,
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
    Refused,
    Failed,
}

/// How one git run ended.
enum Run {
    Exited(std::process::ExitStatus),
    /// `give_way` asked it to end.
    Stopped,
    TimedOut,
}

/// Runs `git gc --auto --quiet` in `repo_dir`, unless the repository's own
/// configuration names a command gc would run. Once `give_way` says so, the
/// run ends, finished or not.
fn collect_garbage(repo_dir: &Path, give_way: impl Fn() -> bool) -> Result<Gc> {
    let process_env = GitWireProcessEnv::capture()?;
    let mut check = git(&process_env, repo_dir)?;
    check.args(["config", "--get-all", GC_COMMAND_KEY]);
    match run(check, &give_way)? {
        // `git config` exits 1 when the key is not set.
        Run::Exited(status) if status.code() == Some(1) => {}
        Run::Exited(status) if status.success() => return Ok(Gc::Refused),
        Run::Exited(_) | Run::TimedOut => return Ok(Gc::Failed),
        Run::Stopped => return Ok(Gc::Stopped),
    }
    let mut gc = git(&process_env, repo_dir)?;
    gc.args(["gc", "--auto", "--quiet"]);
    Ok(match run(gc, &give_way)? {
        Run::Exited(status) if status.success() => Gc::Done,
        Run::Exited(_) | Run::TimedOut => Gc::Failed,
        Run::Stopped => Gc::Stopped,
    })
}

/// A git command on `repo_dir` with a closed environment: no system or
/// global configuration, the pinned settings, nothing on its standard
/// streams.
fn git(process_env: &GitWireProcessEnv, repo_dir: &Path) -> Result<std::process::Command> {
    let mut command = oneiron_spawn::command(process_env.git_binary().as_os_str());
    for pinned in PINNED {
        command.arg("-c").arg(pinned);
    }
    command
        .env_clear()
        .env("GIT_DIR", path_arg(repo_dir)?)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(command)
}

/// Runs `command` as the leader of its own process group, so ending it ends
/// every git it started, for at most [`SERVED_REPOSITORY_GC_TIMEOUT`].
fn run(mut command: std::process::Command, give_way: &impl Fn() -> bool) -> Result<Run> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    let deadline = Instant::now() + SERVED_REPOSITORY_GC_TIMEOUT;
    loop {
        if give_way() {
            end(&mut child);
            return Ok(Run::Stopped);
        }
        if let Some(status) = child.try_wait()? {
            return Ok(Run::Exited(status));
        }
        if Instant::now() >= deadline {
            end(&mut child);
            return Ok(Run::TimedOut);
        }
        std::thread::sleep(POLL);
    }
}

/// Ends the run and every git it started: a terminate first, on which git
/// removes its own lock and temporary files, then a kill for whatever is
/// still there after [`END_GRACE`]. Returns once the leader is reaped and no
/// process of its group is left, or a kill's grace has passed too.
fn end(child: &mut Child) {
    #[cfg(unix)]
    if let Ok(group) = libc::pid_t::try_from(child.id()) {
        for signal in [libc::SIGTERM, libc::SIGKILL] {
            // SAFETY: the group is the child's own, and it is not gone: the
            // leader is unreaped or a member is left, so its id is not reused.
            unsafe {
                libc::kill(-group, signal);
            }
            if group_ended(child, group) {
                return;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
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
