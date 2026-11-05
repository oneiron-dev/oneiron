//! Repository scope identity and the existing redacted Git command bridge.

use std::path::{Path, PathBuf};

use crate::code_snapshot::repo_ref::RepoRef;
use crate::git_wire::bridge::redact_bridged_failure;
use oneiron_base::error::CodeError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

const MAX_REPO_MUTATION_FAILURE_BYTES: usize = 4096;

pub fn truncate_failure(message: &str) -> String {
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

pub fn path_arg(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(Error::Code(CodeError::InvalidRepoMutationRecord(
            "path must be UTF-8",
        )))
}

pub fn utf8_trimmed(bytes: Vec<u8>, context: &'static str) -> Result<String> {
    let text = String::from_utf8(bytes)
        .map_err(|_| Error::Code(CodeError::InvalidRepoMutationRecord(context)))?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

pub fn canonical_repo_ref_for_root(repo_ref: &RepoRef, repo_root: &Path) -> Result<RepoRef> {
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

/// Repo-mutation failures are durable: the queue stores them on the oplog row.
/// They therefore carry only what GitWire's redaction allows — a classified
/// cause, the exit code, and a digest of the diagnostics.
pub fn format_git_failure(args: &[String], code: Option<i32>, stderr: &[u8]) -> String {
    truncate_failure(&redact_bridged_failure(args, code, stderr))
}

pub fn repo_mutation_repo_key(repo_ref: &RepoRef) -> String {
    match repo_ref {
        RepoRef::LocalFolder { path, .. } => format!("local:{path}"),
        RepoRef::GitHubAtCommit { .. } => repo_ref.canonical(),
        RepoRef::LocalCapture { .. } => repo_ref.canonical(),
    }
}
