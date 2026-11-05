//! Core half of `git_wire::mutation_commands`: its store-layer items live in `oneiron_store::git_wire::mutation_commands` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::git_wire::mutation_commands::*;

use crate::error::{CodeError, Error, Result};
use crate::git_wire::{redact_bridged_failure, run_bridged_git_argv};
use crate::store::code_snapshot::RepoRef;
use std::path::{Path, PathBuf};

pub(crate) fn resolve_mutable_repo_root(repo_ref: &RepoRef) -> Result<PathBuf> {
    let RepoRef::LocalFolder { path, .. } = repo_ref else {
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "only local repo_refs can be mutated",
        )));
    };
    let output = run_git_at_path(
        Path::new(path),
        &["rev-parse".to_owned(), "--show-toplevel".to_owned()],
    )?;
    let root = utf8_trimmed(output, "git repo root must be UTF-8")?;
    Ok(PathBuf::from(root).canonicalize()?)
}

pub(crate) fn canonical_mutation_scope(repo_root: &Path) -> Result<String> {
    let repo_ref = RepoRef::LocalFolder {
        path: path_arg(repo_root)?,
        commit: String::new(),
    };
    let bare = run_git_at_path(
        repo_root,
        &["rev-parse".to_owned(), "--is-bare-repository".to_owned()],
    )?;
    let root = if utf8_trimmed(bare, "git bare flag must be UTF-8")? == "true" {
        repo_root.canonicalize()?
    } else {
        resolve_mutable_repo_root(&repo_ref)?
    };
    let canonical = canonical_repo_ref_for_root(&repo_ref, &root)?;
    Ok(repo_mutation_repo_key(&canonical))
}

pub(crate) fn run_git(repo_root: &Path, args: &[String]) -> Result<Vec<u8>> {
    run_git_at_path(repo_root, args)
}

pub(crate) fn run_git_at_path(path: &Path, args: &[String]) -> Result<Vec<u8>> {
    let output = run_bridged_git_argv(path, args)?;
    if output.success {
        return Ok(output.stdout);
    }
    Err(Error::Code(CodeError::RepoMutationFailed(
        format_git_failure(args, output.exit_code, &output.stderr),
    )))
}
