//! Repository scope identity and the existing redacted Git command bridge.

use std::path::{Path, PathBuf};

use crate::error::{CodeError, Error, Result};
use crate::git_wire::{redact_bridged_failure, run_bridged_git_argv};
use crate::store::code_snapshot::RepoRef;

const MAX_REPO_MUTATION_FAILURE_BYTES: usize = 4096;

pub(crate) fn truncate_failure(message: &str) -> String {
    if message.len() <= MAX_REPO_MUTATION_FAILURE_BYTES {
        return message.to_owned();
    }
    let mut end = MAX_REPO_MUTATION_FAILURE_BYTES;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = message[..end].to_owned();
    out.push_str("...");
    out
}

pub(crate) fn path_arg(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(Error::Code(CodeError::InvalidRepoMutationRecord(
            "path must be UTF-8",
        )))
}

pub(crate) fn utf8_trimmed(bytes: Vec<u8>, context: &'static str) -> Result<String> {
    let text = String::from_utf8(bytes)
        .map_err(|_| Error::Code(CodeError::InvalidRepoMutationRecord(context)))?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

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

pub(crate) fn canonical_repo_ref_for_root(repo_ref: &RepoRef, repo_root: &Path) -> Result<RepoRef> {
    let RepoRef::LocalFolder { commit, .. } = repo_ref else {
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "only local repo_refs can be mutated",
        )));
    };
    let path = repo_root
        .to_str()
        .ok_or(Error::Code(CodeError::InvalidRepoMutationRecord(
            "local repo path must be UTF-8",
        )))?
        .to_owned();
    Ok(RepoRef::LocalFolder {
        path,
        commit: commit.clone(),
    })
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

/// Repo-mutation failures are durable: the queue stores them on the oplog row.
/// They therefore carry only what GitWire's redaction allows — a classified
/// cause, the exit code, and a digest of the diagnostics.
fn format_git_failure(args: &[String], code: Option<i32>, stderr: &[u8]) -> String {
    truncate_failure(&redact_bridged_failure(args, code, stderr))
}

pub(crate) fn repo_mutation_repo_key(repo_ref: &RepoRef) -> String {
    match repo_ref {
        RepoRef::LocalFolder { path, .. } => format!("local:{path}"),
        RepoRef::GitHubAtCommit { .. } => repo_ref.canonical(),
    }
}
