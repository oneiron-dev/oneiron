use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::codebase::RepoRef;
use crate::error::{Error, Result};

use super::git::{git_output_optional, run_git, validate_relative_repo_path};
use super::oplog::{REPO_MUTATION_OPLOG_SCHEMA_VERSION, repo_mutation_snapshot_key};
use super::support::{path_arg, sha256_bytes, utf8_trimmed};
use super::types::RepoForkHash;
use super::worktree::{ensure_repo_parent_dirs_no_symlink, write_repo_file_no_symlink};

const MAX_REPO_MUTATION_SNAPSHOT_FILES: usize = 100_000;
const MAX_REPO_MUTATION_SNAPSHOT_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_REPO_MUTATION_SNAPSHOT_FILE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredRepoSnapshot {
    pub(super) schema_version: u8,
    pub(super) head: Option<String>,
    pub(super) entries: Vec<StoredRepoSnapshotEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredRepoSnapshotEntry {
    pub(super) path: String,
    pub(super) kind: StoredRepoSnapshotEntryKind,
    pub(super) executable: bool,
    pub(super) content: Vec<u8>,
    pub(super) symlink_target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum StoredRepoSnapshotEntryKind {
    File,
    Symlink,
}

#[derive(Debug, Default)]
struct SnapshotStats {
    files: usize,
    total_bytes: u64,
}

pub(super) fn capture_repo_snapshot(repo_root: &Path) -> Result<(RepoForkHash, Vec<u8>)> {
    let head = git_output_optional(
        repo_root,
        &[
            "rev-parse".to_owned(),
            "--verify".to_owned(),
            "HEAD".to_owned(),
        ],
    )?
    .map(|bytes| utf8_trimmed(bytes, "git HEAD must be UTF-8"))
    .transpose()?;
    let mut entries = Vec::new();
    let mut stats = SnapshotStats::default();
    collect_snapshot_entries(repo_root, repo_root, &mut entries, &mut stats)?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let snapshot = StoredRepoSnapshot {
        schema_version: REPO_MUTATION_OPLOG_SCHEMA_VERSION,
        head,
        entries,
    };
    let encoded = encode_snapshot(&snapshot)?;
    let hash = sha256_bytes(&encoded);
    Ok((hash, encoded))
}

fn collect_snapshot_entries(
    repo_root: &Path,
    dir: &Path,
    entries: &mut Vec<StoredRepoSnapshotEntry>,
    stats: &mut SnapshotStats,
) -> Result<()> {
    let mut children = fs::read_dir(dir)?.collect::<std::result::Result<Vec<_>, _>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        if child.file_name() == OsStr::new(".git") {
            continue;
        }
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            collect_snapshot_entries(repo_root, &path, entries, stats)?;
            continue;
        }
        let relative = repo_relative_path(repo_root, &path)?;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path)?;
            let target = path_arg(&target)?;
            record_snapshot_entry_size(stats, target.len() as u64)?;
            entries.push(StoredRepoSnapshotEntry {
                path: relative,
                kind: StoredRepoSnapshotEntryKind::Symlink,
                executable: false,
                content: Vec::new(),
                symlink_target: Some(target),
            });
        } else if metadata.file_type().is_file() {
            if metadata.len() > MAX_REPO_MUTATION_SNAPSHOT_FILE_BYTES {
                return Err(Error::InvalidRepoMutationRecord(
                    "repo mutation snapshot file exceeds max bytes",
                ));
            }
            record_snapshot_entry_size(stats, metadata.len())?;
            entries.push(StoredRepoSnapshotEntry {
                path: relative,
                kind: StoredRepoSnapshotEntryKind::File,
                executable: is_executable(&metadata),
                content: fs::read(&path)?,
                symlink_target: None,
            });
        } else {
            return Err(Error::InvalidRepoMutationRecord(
                "repo snapshot supports only files, directories, and symlinks",
            ));
        }
    }
    Ok(())
}

pub(super) fn restore_repo_snapshot(
    vault: &Vault,
    repo_ref: &RepoRef,
    repo_root: &Path,
    fork_hash: RepoForkHash,
) -> Result<()> {
    if !snapshot_recorded_for_repo(vault, repo_ref, fork_hash)? {
        return Err(Error::InvalidRepoMutationRecord(
            "requested repo snapshot forkHash is not recorded for this repo",
        ));
    }
    let key = repo_mutation_snapshot_key(fork_hash);
    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .vault_meta
        .get(&rtxn, &key)?
        .ok_or(Error::InvalidRepoMutationRecord(
            "requested repo snapshot forkHash is unknown",
        ))?
        .to_vec();
    drop(rtxn);
    if sha256_bytes(&raw) != fork_hash {
        return Err(Error::CorruptedIndex(
            "repo mutation snapshot hash mismatch",
        ));
    }
    let snapshot = decode_snapshot(&raw)?;
    let snapshot_head = snapshot.head.clone();
    let desired: BTreeSet<String> = snapshot
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    let mut current = BTreeSet::new();
    let mut dirs = Vec::new();
    collect_restore_inventory(repo_root, repo_root, &mut current, &mut dirs)?;

    for path in current.difference(&desired) {
        remove_existing_path(&repo_root.join(path))?;
    }
    remove_empty_dirs(dirs)?;

    for entry in snapshot.entries {
        validate_relative_repo_path(&entry.path)?;
        let target = repo_root.join(&entry.path);
        if fs::symlink_metadata(&target).is_ok() {
            remove_existing_path(&target)?;
        }
        match entry.kind {
            StoredRepoSnapshotEntryKind::File => {
                write_repo_file_no_symlink(repo_root, &entry.path, &entry.content)?;
                set_executable(&target, entry.executable)?;
            }
            StoredRepoSnapshotEntryKind::Symlink => {
                let target_path = entry
                    .symlink_target
                    .ok_or(Error::InvalidRepoMutationRecord(
                        "symlink snapshot entry missing target",
                    ))?;
                let target = ensure_repo_parent_dirs_no_symlink(repo_root, &entry.path)?;
                create_symlink(Path::new(&target_path), &target)?;
            }
        }
    }
    if let Some(head) = snapshot_head {
        run_git(
            repo_root,
            &["update-ref".to_owned(), "HEAD".to_owned(), head],
        )?;
        run_git(
            repo_root,
            &[
                "read-tree".to_owned(),
                "--reset".to_owned(),
                "HEAD".to_owned(),
            ],
        )?;
    }
    Ok(())
}

fn record_snapshot_entry_size(stats: &mut SnapshotStats, bytes: u64) -> Result<()> {
    stats.files = stats
        .files
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("repo_mutation_snapshot_files"))?;
    if stats.files > MAX_REPO_MUTATION_SNAPSHOT_FILES {
        return Err(Error::InvalidRepoMutationRecord(
            "repo mutation snapshot exceeds max file count",
        ));
    }
    stats.total_bytes = stats
        .total_bytes
        .checked_add(bytes)
        .ok_or(Error::ArithmeticOverflow("repo_mutation_snapshot_bytes"))?;
    if stats.total_bytes > MAX_REPO_MUTATION_SNAPSHOT_TOTAL_BYTES {
        return Err(Error::InvalidRepoMutationRecord(
            "repo mutation snapshot exceeds max total bytes",
        ));
    }
    Ok(())
}

fn snapshot_recorded_for_repo(
    vault: &Vault,
    repo_ref: &RepoRef,
    fork_hash: RepoForkHash,
) -> Result<bool> {
    Ok(vault
        .repo_mutation_oplog_for_canonical(repo_ref)?
        .iter()
        .any(|entry| entry.pre_action_fork_hash == fork_hash))
}

fn collect_restore_inventory(
    repo_root: &Path,
    dir: &Path,
    files: &mut BTreeSet<String>,
    dirs: &mut Vec<PathBuf>,
) -> Result<()> {
    let mut children = fs::read_dir(dir)?.collect::<std::result::Result<Vec<_>, _>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        if child.file_name() == OsStr::new(".git") {
            continue;
        }
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            dirs.push(path.clone());
            collect_restore_inventory(repo_root, &path, files, dirs)?;
        } else if metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            files.insert(repo_relative_path(repo_root, &path)?);
        } else {
            return Err(Error::InvalidRepoMutationRecord(
                "repo restore supports only files, directories, and symlinks",
            ));
        }
    }
    Ok(())
}

fn remove_empty_dirs(mut dirs: Vec<PathBuf>) -> Result<()> {
    dirs.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for dir in dirs {
        if fs::read_dir(&dir)?.next().is_none() {
            fs::remove_dir(dir)?;
        }
    }
    Ok(())
}

fn remove_existing_path(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub(super) fn encode_snapshot(snapshot: &StoredRepoSnapshot) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(snapshot)
        .map_err(|_| Error::InvariantViolation("repo mutation snapshot encode failed"))
}

pub(super) fn decode_snapshot(bytes: &[u8]) -> Result<StoredRepoSnapshot> {
    let snapshot: StoredRepoSnapshot = rmp_serde::from_slice(bytes).map_err(|_| {
        Error::InvalidRepoMutationRecord("repo mutation snapshot is not MessagePack")
    })?;
    if snapshot.schema_version != REPO_MUTATION_OPLOG_SCHEMA_VERSION {
        return Err(Error::InvalidRepoMutationRecord(
            "unsupported repo mutation snapshot schema version",
        ));
    }
    Ok(snapshot)
}

fn repo_relative_path(repo_root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(repo_root)
        .map_err(|_| Error::InvariantViolation("repo path escaped root"))?;
    let mut out = String::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(Error::InvalidRepoMutationRecord(
                "repo snapshot path must be normal",
            ));
        };
        let part = part.to_str().ok_or(Error::InvalidRepoMutationRecord(
            "repo snapshot path must be UTF-8",
        ))?;
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(part);
    }
    validate_relative_repo_path(&out)?;
    Ok(out)
}

fn is_executable(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

fn set_executable(path: &Path, executable: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o755 } else { 0o644 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, executable);
    }
    Ok(())
}

fn create_symlink(target: &Path, link: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (target, link);
        Err(Error::InvalidRepoMutationRecord(
            "symlink repo snapshots are unsupported on this platform",
        ))
    }
}
