//! Core half of `origin::smart_http::maintain`: its store-layer items live in `oneiron_store::origin::smart_http::maintain` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::origin::smart_http::maintain::*;

use super::paths::{ORIGIN_REPO_DIR_SUFFIX, origin_serving_root, validate_repo_name};
use super::serve::repo_common_dir;
use super::serve_cmd::path_arg;
use crate::Vault;
use crate::error::Result;
use crate::git_wire::{
    GIT_WIRE_REPO_LOCK_FILE_NAME, GitWireProcessEnv, try_lock_repository_for_maintenance,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant, SystemTime};

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

/// Runs `git gc --auto --quiet` in `repo_dir`, unless the repository's own
/// configuration names a command gc would run. Once `give_way` says so, the
/// run ends, finished or not.
fn collect_garbage(repo_dir: &Path, give_way: impl Fn() -> bool) -> Result<Gc> {
    let process_env = GitWireProcessEnv::capture()?;
    let mut check = git(&process_env, repo_dir)?;
    check.args(["config", "--get-all", GC_COMMAND_KEY]);
    match run(check, repo_dir, &give_way)? {
        // `git config` exits 1 when the key is not set.
        Run::Exited(status) if status.code() == Some(1) => {}
        Run::Exited(status) if status.success() => return Ok(Gc::Refused),
        Run::Exited(_) | Run::TimedOut => return Ok(Gc::Failed),
        Run::Stopped => return Ok(Gc::Stopped),
    }
    let mut gc = git(&process_env, repo_dir)?;
    gc.args(["gc", "--auto", "--quiet"]);
    Ok(match run(gc, repo_dir, &give_way)? {
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
