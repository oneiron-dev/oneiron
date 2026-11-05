//! Core half of `git_wire::bridge`: its store-layer items live in `oneiron_store::git_wire::bridge` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::git_wire::bridge::*;

use super::argv::validate_argv_token;
use super::config::{GIT_WIRE_BRIDGED_CONFIG_KEYS, GIT_WIRE_MAX_ARGS};
use super::execution_context::GitCommandSpec;
use super::failure::{classify_diagnostics, invalid};
use super::process::spawn_git;
use super::record::hex_lower;
use super::{GitWireProcessEnv, GitWireProcessOutput};
use crate::error::Result;
use std::ffi::OsString;
use std::path::Path;

/// Migration bridge for the `repo_mutation` helper cluster.
///
/// `repo_mutation`'s helpers keep their exact signatures and delegate here so
/// the crate still has exactly one spawn site, one pinned executable, and one
/// closed configuration policy. The argv is validated position by position, the
/// only pre-verb options accepted are the frozen `user.name`/`user.email`
/// identity pairs, and the forbidden repo-mutation verb shapes are rejected.
///
/// Boundary: this entry is `pub(crate)` on purpose. No public arbitrary-vector
/// or shell-string constructor exists anywhere in the module.
pub(crate) fn run_bridged_git_argv(
    repo_root: &Path,
    args: &[String],
) -> Result<GitWireProcessOutput> {
    let process_env = GitWireProcessEnv::capture()?;
    let argv = bridged_argv(args)?;
    let command = GitCommandSpec::bridge(repo_root, args, &argv)?;
    spawn_git(&process_env, &command)
}
