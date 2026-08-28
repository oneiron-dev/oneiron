use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use crate::codebase::CODEBASE_COMMIT_HASH_HEX_LEN;
use crate::codebase::{CODEBASE_FILE_PATH_MAX_BYTES, RepoRef};
use crate::error::{Error, Result};
use crate::git_wire::run_bridged_git_argv;

use super::support::{path_arg, truncate_failure, utf8_trimmed};

const MAX_COMMIT_MESSAGE_BYTES: usize = 4096;
const MAX_BASE_REF_BYTES: usize = 256;

pub(super) fn git_common_dir(repo_root: &Path) -> Result<PathBuf> {
    let output = run_git(
        repo_root,
        &["rev-parse".to_owned(), "--git-common-dir".to_owned()],
    )?;
    let path = PathBuf::from(utf8_trimmed(output, "git common dir must be UTF-8")?);
    let path = if path.is_absolute() {
        path
    } else {
        repo_root.join(path)
    };
    Ok(path.canonicalize()?)
}

pub(super) fn resolve_mutable_repo_root(repo_ref: &RepoRef) -> Result<PathBuf> {
    let RepoRef::LocalFolder { path, .. } = repo_ref else {
        return Err(Error::InvalidRepoMutationRecord(
            "only local repo_refs can be mutated",
        ));
    };
    let output = run_git_at_path(
        Path::new(path),
        &["rev-parse".to_owned(), "--show-toplevel".to_owned()],
    )?;
    let root = utf8_trimmed(output, "git repo root must be UTF-8")?;
    Ok(PathBuf::from(root).canonicalize()?)
}

pub(super) fn canonical_repo_ref_for_root(repo_ref: &RepoRef, repo_root: &Path) -> Result<RepoRef> {
    let RepoRef::LocalFolder { commit, .. } = repo_ref else {
        return Err(Error::InvalidRepoMutationRecord(
            "only local repo_refs can be mutated",
        ));
    };
    let path = repo_root
        .to_str()
        .ok_or(Error::InvalidRepoMutationRecord(
            "local repo path must be UTF-8",
        ))?
        .to_owned();
    Ok(RepoRef::LocalFolder {
        path,
        commit: commit.clone(),
    })
}

#[cfg(test)]
pub(super) fn current_head_commit(repo_root: &Path) -> Result<String> {
    let output = run_git(
        repo_root,
        &[
            "rev-parse".to_owned(),
            "--verify".to_owned(),
            "HEAD".to_owned(),
        ],
    )?;
    let commit = utf8_trimmed(output, "git HEAD commit must be UTF-8")?;
    if commit.len() != CODEBASE_COMMIT_HASH_HEX_LEN
        || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(Error::InvalidRepoMutationRecord(
            "git HEAD commit must be a 40-hex hash",
        ));
    }
    Ok(commit.to_ascii_lowercase())
}

pub(super) fn validate_relative_repo_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > CODEBASE_FILE_PATH_MAX_BYTES {
        return Err(Error::InvalidRepoMutationRecord(
            "repo mutation path must be non-empty and at most 4096 bytes",
        ));
    }
    if path.contains('\\') {
        return Err(Error::InvalidRepoMutationRecord(
            "repo mutation path must use forward slashes",
        ));
    }
    let parsed = Path::new(path);
    if parsed.is_absolute() {
        return Err(Error::InvalidRepoMutationRecord(
            "repo mutation path must be repository-relative",
        ));
    }
    let mut has_component = false;
    for component in parsed.components() {
        match component {
            Component::Normal(part) => {
                if part == OsStr::new(".git") {
                    return Err(Error::InvalidRepoMutationRecord(
                        "repo mutation path must not target .git",
                    ));
                }
                has_component = true;
            }
            _ => {
                return Err(Error::InvalidRepoMutationRecord(
                    "repo mutation path must not contain . or .. components",
                ));
            }
        }
    }
    if !has_component {
        return Err(Error::InvalidRepoMutationRecord(
            "repo mutation path must contain a file component",
        ));
    }
    Ok(())
}

pub(super) fn validate_commit_message(message: &str) -> Result<()> {
    if message.is_empty() || message.len() > MAX_COMMIT_MESSAGE_BYTES || message.contains('\0') {
        return Err(Error::InvalidRepoMutationRecord(
            "commit message must be non-empty, bounded, and contain no NUL",
        ));
    }
    Ok(())
}

pub(super) fn validate_base_ref(base_ref: &str) -> Result<()> {
    if base_ref.is_empty()
        || base_ref.len() > MAX_BASE_REF_BYTES
        || base_ref.contains('\0')
        || base_ref.starts_with('-')
    {
        return Err(Error::InvalidRepoMutationRecord(
            "worktree base ref must be non-empty, bounded, contain no NUL, and not start with '-'",
        ));
    }
    Ok(())
}

pub(super) fn validate_git_ref_label(label: &str) -> Result<()> {
    validate_base_ref(label)?;
    if label.starts_with('/')
        || label.ends_with('/')
        || label.contains("//")
        || label.contains("..")
        || label.contains("@{")
        || label.ends_with(".lock")
        || label.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(Error::InvalidRepoMutationRecord(
            "git ref label must be a safe branch/ref label",
        ));
    }
    for part in label.split('/') {
        if part.is_empty() || part == "." || part.ends_with(".lock") {
            return Err(Error::InvalidRepoMutationRecord(
                "git ref label must be a safe branch/ref label",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_git_object_hash(hash: &str, context: &'static str) -> Result<()> {
    if hash.len() != CODEBASE_COMMIT_HASH_HEX_LEN
        || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(Error::InvalidRepoMutationRecord(context));
    }
    Ok(())
}

pub(super) fn validate_worktree_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(Error::InvalidRepoMutationRecord(
            "worktree path must be non-empty",
        ));
    }
    path_arg(path)?;
    Ok(())
}

// RC6 (ARCH-0068): the helper cluster below is repo mutation's only route to
// git, and every one of these helpers now delegates to the GitWire migration
// bridge (`crate::git_wire::run_bridged_git_argv`). GitWire owns the single
// `Command` construction, the cleared environment, the pinned
// `core.hooksPath`/`credential.helper` segments, and the argv validation; this
// file keeps only the repo-mutation error shapes its siblings depend on.
// Signatures are deliberately unchanged so every call site, and the `cfg(test)`
// re-imports in `repo_mutation/mod.rs`, keep resolving exactly as before.

pub(super) fn run_git(repo_root: &Path, args: &[String]) -> Result<Vec<u8>> {
    run_git_at_path(repo_root, args)
}

pub(super) fn git_status_success(path: &Path, args: &[String]) -> Result<bool> {
    Ok(run_bridged_git_argv(path, args)?.success)
}

pub(super) fn run_git_allow_exit_codes(
    path: &Path,
    args: &[String],
    allowed_codes: &[i32],
) -> Result<Vec<u8>> {
    let output = run_bridged_git_argv(path, args)?;
    if output
        .exit_code
        .is_some_and(|code| allowed_codes.contains(&code))
    {
        return Ok(output.stdout);
    }
    if output.success && allowed_codes.contains(&0) {
        return Ok(output.stdout);
    }
    Err(Error::InvalidRepoMutationRecord(
        "git command failed with an unexpected exit code",
    ))
}

pub(super) fn run_git_at_path(path: &Path, args: &[String]) -> Result<Vec<u8>> {
    let output = run_bridged_git_argv(path, args)?;
    if output.success {
        return Ok(output.stdout);
    }
    Err(Error::RepoMutationFailed(format_git_failure(
        args,
        output.exit_code,
        &output.stderr,
    )))
}

pub(super) fn git_output_optional(repo_root: &Path, args: &[String]) -> Result<Option<Vec<u8>>> {
    let output = run_bridged_git_argv(repo_root, args)?;
    if output.success {
        Ok(Some(output.stdout))
    } else {
        Ok(None)
    }
}

/// Whether a staged commit object is already durable in the repository.
///
/// RC6 two-phase: the queue verifies this after the object-producing phase and
/// before the LMDB transaction that writes the prepared row, so a prepared row
/// — and the ref advance it authorises — can never name an object set the
/// repository does not have.
pub(super) fn git_commit_object_available(repo_root: &Path, commit: &str) -> Result<bool> {
    validate_git_object_hash(commit, "staged commit must be a 40-hex commit")?;
    git_status_success(
        repo_root,
        &[
            "cat-file".to_owned(),
            "-e".to_owned(),
            format!("{commit}^{{commit}}"),
        ],
    )
}

fn format_git_failure(args: &[String], code: Option<i32>, stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr);
    let stderr = stderr.trim();
    let message = format!("git {} exited with {:?}: {}", args.join(" "), code, stderr);
    truncate_failure(&message)
}
