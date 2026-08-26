use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{Error, Result};

use super::git::{git_common_dir, run_git, validate_relative_repo_path};
use super::queue::PreparedCommitFile;
use super::support::{hex_bytes, now_millis, path_arg, sha256_bytes, utf8_trimmed};

const REPO_MUTATION_WORKTREE_PREFIX: &str = "oneiron-repo-mutation-";

static REPO_MUTATION_WORKTREE_COUNTER: AtomicU64 = AtomicU64::new(1);

pub(super) fn prepare_commit_file_through_queue_worktree(
    repo_root: &Path,
    path: &str,
    content: &[u8],
    message: &str,
) -> Result<PreparedCommitFile> {
    let base_head = utf8_trimmed(
        run_git(
            repo_root,
            &[
                "rev-parse".to_owned(),
                "--verify".to_owned(),
                "HEAD".to_owned(),
            ],
        )?,
        "git HEAD must be UTF-8",
    )?;
    let worktree_path = create_queue_worktree(repo_root)?;
    let preparation = (|| -> Result<PreparedCommitFile> {
        write_repo_file_no_symlink(&worktree_path, path, content)?;
        run_git(
            &worktree_path,
            &["add".to_owned(), "--".to_owned(), path.to_owned()],
        )?;
        run_git(
            &worktree_path,
            &[
                "-c".to_owned(),
                "user.name=Oneiron".to_owned(),
                "-c".to_owned(),
                "user.email=oneiron@example.invalid".to_owned(),
                "commit".to_owned(),
                "-m".to_owned(),
                message.to_owned(),
                "--only".to_owned(),
                "--".to_owned(),
                path.to_owned(),
            ],
        )?;
        let new_head = utf8_trimmed(
            run_git(
                &worktree_path,
                &[
                    "rev-parse".to_owned(),
                    "--verify".to_owned(),
                    "HEAD".to_owned(),
                ],
            )?,
            "git HEAD must be UTF-8",
        )?;
        Ok(PreparedCommitFile {
            worktree_path: worktree_path.clone(),
            base_head,
            new_head,
        })
    })();
    match preparation {
        Ok(prepared) => Ok(prepared),
        Err(error) => {
            let _ = remove_queue_worktree(repo_root, &worktree_path);
            Err(error)
        }
    }
}

pub(super) fn apply_prepared_commit_file(
    repo_root: &Path,
    path: &str,
    content: &[u8],
    prepared: &PreparedCommitFile,
) -> Result<()> {
    write_repo_file_no_symlink(repo_root, path, content)?;
    run_git(
        repo_root,
        &[
            "update-ref".to_owned(),
            "HEAD".to_owned(),
            prepared.new_head.clone(),
            prepared.base_head.clone(),
        ],
    )?;
    run_git(
        repo_root,
        &["add".to_owned(), "--".to_owned(), path.to_owned()],
    )?;
    Ok(())
}

pub(super) fn create_queue_worktree(repo_root: &Path) -> Result<PathBuf> {
    let worktree_path = queue_owned_worktree_path(repo_root)?;
    run_git(
        repo_root,
        &[
            "worktree".to_owned(),
            "add".to_owned(),
            "--detach".to_owned(),
            "--".to_owned(),
            path_arg(&worktree_path)?,
            "HEAD".to_owned(),
        ],
    )?;
    Ok(worktree_path)
}

pub(super) fn prune_queue_owned_worktrees(repo_root: &Path) -> Result<()> {
    let output = run_git(
        repo_root,
        &[
            "worktree".to_owned(),
            "list".to_owned(),
            "--porcelain".to_owned(),
            "-z".to_owned(),
        ],
    )?;
    for field in output.split(|byte| *byte == 0) {
        let Some(path) = field.strip_prefix(b"worktree ") else {
            continue;
        };
        let Ok(path) = std::str::from_utf8(path) else {
            continue;
        };
        let path = Path::new(path);
        if is_queue_owned_worktree_path(path) {
            let _ = remove_queue_worktree(repo_root, path);
        }
    }
    Ok(())
}

pub(super) fn is_queue_owned_worktree_path(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(parent) = parent.canonicalize() else {
        return false;
    };
    let Ok(temp_dir) = std::env::temp_dir().canonicalize() else {
        return false;
    };
    if parent != temp_dir {
        return false;
    }
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    let Some(suffix) = name.strip_prefix(REPO_MUTATION_WORKTREE_PREFIX) else {
        return false;
    };
    suffix.len() == 24 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn remove_queue_worktree(repo_root: &Path, worktree_path: &Path) -> Result<()> {
    let result = run_git(
        repo_root,
        &[
            "worktree".to_owned(),
            "remove".to_owned(),
            "--force".to_owned(),
            "--".to_owned(),
            path_arg(worktree_path)?,
        ],
    );
    if worktree_path.exists() {
        let _ = fs::remove_dir_all(worktree_path);
    }
    result.map(|_| ())
}

fn queue_owned_worktree_path(repo_root: &Path) -> Result<PathBuf> {
    let common_dir = git_common_dir(repo_root)?;
    for _ in 0..16 {
        let counter = REPO_MUTATION_WORKTREE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let seed = format!(
            "{}:{}:{}:{}",
            common_dir.display(),
            std::process::id(),
            now_millis(),
            counter
        );
        let suffix = &hex_bytes(&sha256_bytes(seed.as_bytes()))[..24];
        let path = std::env::temp_dir().join(format!("{REPO_MUTATION_WORKTREE_PREFIX}{suffix}"));
        if !path.exists() {
            return Ok(path);
        }
    }
    Err(Error::InvalidRepoMutationRecord(
        "unable to allocate queue-owned worktree path",
    ))
}

pub(super) fn write_repo_file_no_symlink(
    repo_root: &Path,
    path: &str,
    content: &[u8],
) -> Result<()> {
    let target = safe_repo_file_target(repo_root, path)?;
    write_file_no_follow(&target, content)
}

fn safe_repo_file_target(repo_root: &Path, path: &str) -> Result<PathBuf> {
    let target = ensure_repo_parent_dirs_no_symlink(repo_root, path)?;
    match fs::symlink_metadata(&target) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::InvalidRepoMutationRecord(
            "repo mutation path must not traverse symlinks",
        )),
        Ok(metadata) if metadata.file_type().is_file() => Ok(target),
        Ok(_) => Err(Error::InvalidRepoMutationRecord(
            "repo mutation target must be a regular file or absent",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(target),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn ensure_repo_parent_dirs_no_symlink(repo_root: &Path, path: &str) -> Result<PathBuf> {
    validate_relative_repo_path(path)?;
    let mut current = repo_root.to_path_buf();
    let mut components = Path::new(path).components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(part) = component else {
            return Err(Error::InvalidRepoMutationRecord(
                "repo mutation path must contain only normal components",
            ));
        };
        current.push(part);
        let is_leaf = components.peek().is_none();
        if is_leaf {
            return Ok(current);
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::InvalidRepoMutationRecord(
                    "repo mutation path must not traverse symlinks",
                ));
            }
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(Error::InvalidRepoMutationRecord(
                    "repo mutation parent path must be a directory",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(current)
}

#[cfg(unix)]
fn write_file_no_follow(path: &Path, content: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(content)?;
    file.flush()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_file_no_follow(path: &Path, content: &[u8]) -> Result<()> {
    fs::write(path, content)?;
    Ok(())
}
