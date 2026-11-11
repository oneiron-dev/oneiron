//! Capture, validation and restore of repository working-tree snapshots.
//! The restore entry is `restore_repo_snapshot`.
//! `pinned` owns the re-exported `RepoPinnedBase`; snapshot row definitions are local.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::codebase::RepoRef;
use crate::error::{Error, Result};
use crate::scan_check::{EngineScan, ScanCount};
use crate::secret_snapshot::{SnapshotExclusionSet, SnapshotWithhold};

use super::git::{git_output_optional, repo_path_on_disk, run_git, validate_relative_repo_path};
use super::oplog::{REPO_MUTATION_OPLOG_SCHEMA_VERSION, SNAPSHOT, repo_mutation_snapshot_key};
use super::support::{path_arg, sha256_bytes, utf8_trimmed};
use super::types::RepoForkHash;
use super::worktree::{ensure_repo_parent_dirs_no_symlink, write_repo_file_no_symlink};
use crate::error::CodeError;
use crate::git_wire::bundle_tree::{
    BundleTreeEdit, gitlink_index_entries, gitlink_paths_at, stage_bundle_tree_edits,
};
use crate::git_wire::{git_path_string, git_path_text_of_os};
use crate::store::code_tree_blob::MODE_GITLINK;

mod capture;
mod checkout;
mod pinned;
pub(crate) use capture::CaptureEntry;
pub(crate) use checkout::visit_code_capture_files;
pub(super) use pinned::RepoPinnedBase;

/// The bytes one snapshot holds in memory: a machine floor, not a count.
const MAX_REPO_MUTATION_SNAPSHOT_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
/// Paths one restore's `git reset` names, under GitWire's argv bound.
const RESTORE_INDEX_PATHS_PER_CALL: usize = 56;
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
    /// An index gitlink: content is its OID, never the linked repository.
    Gitlink,
    /// A file snapshot custody keeps out ([`SnapshotCustody`]): its path and
    /// mode, none of its bytes. A restore leaves the file the checkout holds
    /// there as it is.
    Withheld,
}

/// Snapshot custody (ARCH-0069 S4/S5) over the checkout a mutation snapshots
/// (OF-067): the declared-path exclusion and undeclared-secret quarantine a
/// codebase snapshot keeps, read once per capture. A file it withholds is
/// stored [`StoredRepoSnapshotEntryKind::Withheld`], so its bytes never reach
/// a snapshot row and a restore never deletes it.
pub(super) struct SnapshotCustody {
    exclusions: SnapshotExclusionSet,
    root: Option<String>,
}

impl SnapshotCustody {
    pub(super) fn of(vault: &Vault, repo_root: &Path) -> Result<Self> {
        let txn = vault.store.env.read_txn()?;
        Ok(Self {
            exclusions: SnapshotExclusionSet::for_every_project(vault, &txn)?,
            root: repo_root
                .to_str()
                .map(|root| root.trim_end_matches('/').to_owned()),
        })
    }

    /// Why the policy keeps `content` at `path` out of a snapshot, if it does.
    pub(super) fn withholds(&self, path: &str, content: &[u8]) -> Option<SnapshotWithhold> {
        self.exclusions
            .withholds(path, content, self.root.as_deref())
    }

    /// A file's entry as the policy keeps it.
    pub(super) fn file(
        &self,
        path: String,
        executable: bool,
        content: Vec<u8>,
    ) -> StoredRepoSnapshotEntry {
        let (kind, content) = match self.withholds(&path, &content) {
            None => (StoredRepoSnapshotEntryKind::File, content),
            Some(_) => (StoredRepoSnapshotEntryKind::Withheld, Vec::new()),
        };
        StoredRepoSnapshotEntry {
            path,
            kind,
            executable,
            content,
            symlink_target: None,
        }
    }

    /// A gitlink's OID under the same path and byte custody as a file.
    pub(super) fn gitlink(&self, path: String, oid: Vec<u8>) -> StoredRepoSnapshotEntry {
        let mut entry = self.file(path, false, oid);
        if entry.kind == StoredRepoSnapshotEntryKind::File {
            entry.kind = StoredRepoSnapshotEntryKind::Gitlink;
        }
        entry
    }

    /// A symlink's entry as the policy keeps it: a target the policy
    /// withholds is kept out as a file's bytes are (FIX 8840).
    pub(super) fn symlink(&self, path: String, target: String) -> StoredRepoSnapshotEntry {
        let (kind, symlink_target) = match self.withholds(&path, target.as_bytes()) {
            None => (StoredRepoSnapshotEntryKind::Symlink, Some(target)),
            Some(_) => (StoredRepoSnapshotEntryKind::Withheld, None),
        };
        StoredRepoSnapshotEntry {
            path,
            kind,
            executable: false,
            content: Vec::new(),
            symlink_target,
        }
    }
}

/// One capture's walk: its entries counted against their threshold row
/// (rule 5, FIX 8835) and the bytes it holds.
struct SnapshotStats {
    files: ScanCount,
    total_bytes: u64,
}

pub(super) fn capture_repo_snapshot(
    vault: &Vault,
    repo_root: &Path,
) -> Result<(RepoForkHash, Vec<u8>)> {
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
    let custody = SnapshotCustody::of(vault, repo_root)?;
    let mut entries = Vec::new();
    // Scoped by the checkout's path, hashed to a fixed width.
    let scope = blake3::hash(repo_root.as_os_str().as_encoded_bytes());
    let mut stats = SnapshotStats {
        files: ScanCount::start_at(
            EngineScan::RepoSnapshotFiles,
            &scope.as_bytes()[..16],
            vault.scan_threshold(EngineScan::RepoSnapshotFiles)?,
        ),
        total_bytes: 0,
    };
    let gitlinks = gitlink_index_entries(repo_root)?;
    let indexed_paths: BTreeSet<_> = gitlinks.keys().cloned().collect();
    let mut linked_paths = indexed_paths.clone();
    if let Some(head) = &head {
        linked_paths.extend(gitlink_paths_at(repo_root, head)?);
    }
    for (path, oid) in &gitlinks {
        validate_relative_repo_path(path)?;
        record_snapshot_entry_size(&mut stats, oid.len() as u64)?;
        entries.push(custody.gitlink(path.clone(), oid.clone()));
    }
    collect_snapshot_entries(
        repo_root,
        repo_root,
        &custody,
        &indexed_paths,
        &linked_paths,
        &mut entries,
        &mut stats,
    )?;
    stats.files.finish(vault);
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let snapshot = StoredRepoSnapshot {
        schema_version: REPO_MUTATION_OPLOG_SCHEMA_VERSION,
        head,
        entries,
    };
    let encoded = encode_snapshot(&snapshot)?;
    let hash = *blake3::hash(&encoded).as_bytes();
    Ok((hash, encoded))
}

fn collect_snapshot_entries(
    repo_root: &Path,
    dir: &Path,
    custody: &SnapshotCustody,
    indexed_paths: &BTreeSet<String>,
    linked_paths: &BTreeSet<String>,
    entries: &mut Vec<StoredRepoSnapshotEntry>,
    stats: &mut SnapshotStats,
) -> Result<()> {
    checkout::visit_checkout_entries(
        repo_root,
        dir,
        indexed_paths,
        linked_paths,
        &mut |path, relative, metadata| {
            if metadata.file_type().is_symlink() {
                let target = fs::read_link(path)?;
                let target = path_arg(&target)?;
                record_snapshot_entry_size(stats, target.len() as u64)?;
                entries.push(custody.symlink(relative, target));
            } else if metadata.file_type().is_file() {
                if metadata.len() > MAX_REPO_MUTATION_SNAPSHOT_FILE_BYTES {
                    return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                        "repo mutation snapshot file exceeds max bytes",
                    )));
                }
                record_snapshot_entry_size(stats, metadata.len())?;
                entries.push(custody.file(relative, is_executable(metadata), fs::read(path)?));
            } else {
                return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                    "repo snapshot supports only files, directories, and symlinks",
                )));
            }
            Ok(())
        },
    )
}

pub(super) fn restore_repo_snapshot(
    vault: &Vault,
    repo_ref: &RepoRef,
    repo_root: &Path,
    fork_hash: RepoForkHash,
) -> Result<()> {
    if !snapshot_recorded_for_repo(vault, repo_ref, fork_hash)? {
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "requested repo snapshot forkHash is not recorded for this repo",
        )));
    }
    let key = repo_mutation_snapshot_key(fork_hash);
    let rtxn = vault.store.env.read_txn()?;
    let snapshot = SNAPSHOT.get(&vault.store, &rtxn, &key)?.ok_or(Error::Code(
        CodeError::InvalidRepoMutationRecord("requested repo snapshot forkHash is unknown"),
    ))?;
    let raw = SNAPSHOT.encode_value(&snapshot)?;
    // A file the lift sweep marked is left as a withheld one is (OF-067).
    let lifted = super::lift::lifted_entries_in_txn(vault, &rtxn, &key, &raw)?;
    drop(rtxn);
    if *blake3::hash(&raw).as_bytes() != fork_hash && sha256_bytes(&raw) != fork_hash {
        return Err(Error::CorruptedIndex(
            "repo mutation snapshot hash mismatch",
        ));
    }
    let snapshot = require_snapshot_schema(snapshot)?;
    let snapshot_head = snapshot.head.clone();
    let desired: BTreeSet<String> = snapshot
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    let mut current = BTreeSet::new();
    let mut dirs = Vec::new();
    let current_gitlinks = gitlink_index_entries(repo_root)?;
    let mut opaque_paths: BTreeSet<_> = current_gitlinks.keys().cloned().collect();
    opaque_paths.extend(
        snapshot
            .entries
            .iter()
            .filter(|entry| entry.kind == StoredRepoSnapshotEntryKind::Gitlink)
            .map(|entry| entry.path.clone()),
    );
    let mut linked_paths = opaque_paths.clone();
    if let Some(head) = git_output_optional(
        repo_root,
        &[
            "rev-parse".to_owned(),
            "--verify".to_owned(),
            "HEAD".to_owned(),
        ],
    )? {
        linked_paths.extend(gitlink_paths_at(
            repo_root,
            &utf8_trimmed(head, "git HEAD must be UTF-8")?,
        )?);
    }
    let mut residual_paths = BTreeSet::new();
    collect_restore_inventory(
        repo_root,
        repo_root,
        &opaque_paths,
        &linked_paths,
        &mut current,
        &mut dirs,
        &mut residual_paths,
    )?;
    // P1#2 (FIX 5365 R2): `reset_restored_index` can reintroduce a gitlink
    // from `snapshot_head` (staged deletion: HEAD A holds `s`, entries omit
    // `s`, current C deleted it; update-ref to A plus reset revives `G`).
    // AFTER inventory (working-tree opacity stays R1: a snapshot-head-only
    // file replacement is NOT an opaque dir), extend with the snapshot
    // HEAD links so `removed_links` (absent from DESIRED all entries)
    // covers post-reset revivals. Desired file/symlink paths stay OUT
    // (desired is ALL entries), preserving R1case4; their index overwrite
    // stages later via `linked_paths.contains` below.
    if let Some(head) = &snapshot_head {
        linked_paths.extend(gitlink_paths_at(repo_root, head)?);
    }
    let removed_links: Vec<_> = linked_paths.difference(&desired).cloned().collect();
    // P1#1 (FIX 5365 R2): residual checkouts the inventory skipped via a
    // `.git` marker are NOT in `linked_paths` (no HEAD/index gitlink), yet
    // replacing one (or an ancestor dir) with a file/symlink would
    // recursively delete private checkout data (ruled Engine 15:01: never
    // recurse into or delete a linked checkout). Refuse BEFORE any
    // deletion; equality AND ancestor matter, not only strict descendants.
    // R1 HEAD-only captures (no marker, ordinary working file) are NOT in
    // `residual_paths`, so they still stage via `linked_paths` above.
    for entry in &snapshot.entries {
        if entry.kind == StoredRepoSnapshotEntryKind::Gitlink {
            continue;
        }
        if entry.kind == StoredRepoSnapshotEntryKind::Withheld {
            continue;
        }
        if lifted.contains(&entry.path) {
            continue;
        }
        for repo in &residual_paths {
            if entry
                .path
                .strip_prefix(repo.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
            {
                return Err(Error::InvalidClaimBody(
                    "a snapshot cannot enter a linked repository",
                ));
            }
            if entry.path == *repo {
                return Err(Error::InvalidClaimBody(
                    "a snapshot cannot replace a linked repository",
                ));
            }
            if repo
                .strip_prefix(entry.path.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
            {
                return Err(Error::InvalidClaimBody(
                    "a snapshot cannot replace a linked repository",
                ));
            }
        }
    }

    // The paths this restore changes: only their index entries are reset.
    let mut changed: BTreeSet<String> = current.difference(&desired).cloned().collect();
    for path in &changed {
        remove_existing_path(&repo_path_on_disk(repo_root, path)?)?;
    }
    remove_empty_dirs(dirs)?;

    let mut index_edits = Vec::new();
    for entry in snapshot.entries {
        validate_relative_repo_path(&entry.path)?;
        if entry.kind == StoredRepoSnapshotEntryKind::Withheld || lifted.contains(&entry.path) {
            continue;
        }
        if entry.kind == StoredRepoSnapshotEntryKind::Gitlink {
            changed.insert(entry.path.clone());
            index_edits.push(BundleTreeEdit {
                path: entry.path,
                content: Some(entry.content),
                mode: MODE_GITLINK,
            });
            continue;
        }
        if linked_paths.iter().any(|parent| {
            entry
                .path
                .strip_prefix(parent.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
        }) {
            return Err(Error::InvalidClaimBody(
                "a snapshot cannot enter a linked repository",
            ));
        }
        if linked_paths.contains(&entry.path) {
            let (content, mode) = match entry.kind {
                StoredRepoSnapshotEntryKind::File => (
                    entry.content.clone(),
                    if entry.executable {
                        0o100_755
                    } else {
                        0o100_644
                    },
                ),
                StoredRepoSnapshotEntryKind::Symlink => (
                    entry
                        .symlink_target
                        .as_ref()
                        .ok_or(Error::CorruptedIndex("symlink target missing"))?
                        .as_bytes()
                        .to_vec(),
                    0o120_000,
                ),
                _ => unreachable!("gitlinks and withheld entries handled above"),
            };
            index_edits.push(BundleTreeEdit {
                path: entry.path.clone(),
                content: Some(content),
                mode,
            });
        }
        let target = repo_path_on_disk(repo_root, &entry.path)?;
        if checkout_holds_entry(&target, &entry)? {
            continue;
        }
        changed.insert(entry.path.clone());
        if let Ok(metadata) = fs::symlink_metadata(&target) {
            let contains_gitlink = linked_paths.iter().any(|path| {
                path == &entry.path
                    || path
                        .strip_prefix(entry.path.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            });
            if contains_gitlink && metadata.is_dir() {
                // A populated linked checkout is not this snapshot's file tree.
                fs::remove_dir(&target)?;
            } else {
                remove_existing_path(&target)?;
            }
        }
        match entry.kind {
            StoredRepoSnapshotEntryKind::File => {
                write_repo_file_no_symlink(repo_root, &entry.path, &entry.content)?;
                set_executable(&target, entry.executable)?;
            }
            StoredRepoSnapshotEntryKind::Symlink => {
                let target_path = entry.symlink_target.ok_or(Error::Code(
                    CodeError::InvalidRepoMutationRecord("symlink snapshot entry missing target"),
                ))?;
                let target = ensure_repo_parent_dirs_no_symlink(repo_root, &entry.path)?;
                create_symlink(Path::new(&target_path), &target)?;
            }
            StoredRepoSnapshotEntryKind::Gitlink | StoredRepoSnapshotEntryKind::Withheld => {}
        }
    }
    if let Some(head) = snapshot_head {
        let moved_from = git_output_optional(
            repo_root,
            &[
                "rev-parse".to_owned(),
                "--verify".to_owned(),
                "HEAD".to_owned(),
            ],
        )?
        .map(|bytes| utf8_trimmed(bytes, "git HEAD must be UTF-8"))
        .transpose()?;
        run_git(
            repo_root,
            &["update-ref".to_owned(), "HEAD".to_owned(), head],
        )?;
        reset_restored_index(repo_root, moved_from.as_deref(), changed)?;
    }
    for path in removed_links {
        run_git(
            repo_root,
            &[
                "update-index".to_owned(),
                "--force-remove".to_owned(),
                "--".to_owned(),
                path,
            ],
        )?;
    }
    stage_bundle_tree_edits(repo_root, &index_edits, false)?;
    Ok(())
}

/// Whether the checkout already holds `entry` at `target`, so the restore
/// leaves it, and its staged entry, as they are.
fn checkout_holds_entry(target: &Path, entry: &StoredRepoSnapshotEntry) -> Result<bool> {
    let Ok(metadata) = fs::symlink_metadata(target) else {
        return Ok(false);
    };
    Ok(match entry.kind {
        StoredRepoSnapshotEntryKind::File => {
            metadata.file_type().is_file()
                && is_executable(&metadata) == entry.executable
                && metadata.len() == entry.content.len() as u64
                && fs::read(target)? == entry.content
        }
        StoredRepoSnapshotEntryKind::Symlink => {
            metadata.file_type().is_symlink()
                && entry.symlink_target.as_deref().map(Path::new)
                    == Some(fs::read_link(target)?.as_path())
        }
        StoredRepoSnapshotEntryKind::Gitlink | StoredRepoSnapshotEntryKind::Withheld => true,
    })
}

/// Brings the index to the restored HEAD only where the restore moved the
/// checkout: a path whose bytes it rewrote or whose HEAD entry the move
/// changed takes HEAD's entry, and every other staged entry is kept as it
/// was, so a staged version the restore never touched survives it (FIX
/// 8836). A checkout that had no HEAD resets the whole index, as before.
fn reset_restored_index(
    repo_root: &Path,
    moved_from: Option<&str>,
    mut paths: BTreeSet<String>,
) -> Result<()> {
    let Some(from) = moved_from else {
        run_git(
            repo_root,
            &[
                "read-tree".to_owned(),
                "--reset".to_owned(),
                "HEAD".to_owned(),
            ],
        )?;
        return Ok(());
    };
    let moved = run_git(
        repo_root,
        &[
            "diff".to_owned(),
            "--name-only".to_owned(),
            "-z".to_owned(),
            "--no-renames".to_owned(),
            "--no-ext-diff".to_owned(),
            from.to_owned(),
            "HEAD".to_owned(),
        ],
    )?;
    for path in moved
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        // A name outside UTF-8 keeps its bytes as a Git path's text; the
        // bridged argv turns the pathspec back into them (FIX 21326).
        paths.insert(git_path_string(path.to_vec())?);
    }
    let paths: Vec<String> = paths.into_iter().collect();
    for chunk in paths.chunks(RESTORE_INDEX_PATHS_PER_CALL) {
        let mut args = vec![
            "reset".to_owned(),
            "-q".to_owned(),
            "HEAD".to_owned(),
            "--".to_owned(),
        ];
        args.extend(chunk.iter().map(|path| format!(":(literal){path}")));
        run_git(repo_root, &args)?;
    }
    Ok(())
}

fn record_snapshot_entry_size(stats: &mut SnapshotStats, bytes: u64) -> Result<()> {
    stats.files.row();
    stats.total_bytes = stats
        .total_bytes
        .checked_add(bytes)
        .ok_or(Error::ArithmeticOverflow("repo_mutation_snapshot_bytes"))?;
    if stats.total_bytes > MAX_REPO_MUTATION_SNAPSHOT_TOTAL_BYTES {
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "repo mutation snapshot exceeds max total bytes",
        )));
    }
    Ok(())
}

pub(super) fn snapshot_recorded_for_repo(
    vault: &Vault,
    repo_ref: &RepoRef,
    fork_hash: RepoForkHash,
) -> Result<bool> {
    Ok(vault
        .repo_mutation_oplog_for_canonical(repo_ref)?
        .iter()
        .any(|entry| entry.pre_action_fork_hash == fork_hash)
        || super::proposal::proposal_snapshot_recorded(vault, repo_ref, fork_hash)?)
}

fn collect_restore_inventory(
    repo_root: &Path,
    dir: &Path,
    opaque_paths: &BTreeSet<String>,
    linked_paths: &BTreeSet<String>,
    files: &mut BTreeSet<String>,
    dirs: &mut Vec<PathBuf>,
    residual: &mut BTreeSet<String>,
) -> Result<()> {
    let mut children = fs::read_dir(dir)?.collect::<std::result::Result<Vec<_>, _>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        if child.file_name() == OsStr::new(".git") {
            continue;
        }
        let path = child.path();
        let relative = repo_relative_path(repo_root, &path)?;
        if opaque_paths.contains(&relative) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            // P1#1 (FIX 5365 R2): carry the actual marker-discovered
            // boundary (symlink_metadata only, no follow/read) into the
            // overlap guards; the caller refuses file/symlink replacement
            // of this dir or any ancestor BEFORE any deletion.
            if nested_repository(&path)? {
                residual.insert(relative);
                continue;
            }
            if linked_paths.contains(&relative) {
                continue;
            }
            dirs.push(path.clone());
            collect_restore_inventory(
                repo_root,
                &path,
                opaque_paths,
                linked_paths,
                files,
                dirs,
                residual,
            )?;
        } else if metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            files.insert(relative);
        } else {
            return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                "repo restore supports only files, directories, and symlinks",
            )));
        }
    }
    Ok(())
}

/// A nested checkout stays opaque even after its outer gitlink is removed.
fn nested_repository(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path.join(".git")) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
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

/// The [`SNAPSHOT`] codec, kept callable directly: [`capture_repo_snapshot`]
/// needs the encoded bytes themselves (their hash IS the row's key), and a
/// few readers still hold raw bytes they must reverify before trusting.
pub(super) fn encode_snapshot(snapshot: &StoredRepoSnapshot) -> Result<Vec<u8>> {
    SNAPSHOT.encode_value(snapshot)
}

/// Decodes and re-checks the schema version [`SNAPSHOT`]'s generic codec has
/// no notion of.
pub(super) fn decode_snapshot(bytes: &[u8]) -> Result<StoredRepoSnapshot> {
    require_snapshot_schema(SNAPSHOT.decode_value(bytes)?)
}

pub(super) fn require_snapshot_schema(snapshot: StoredRepoSnapshot) -> Result<StoredRepoSnapshot> {
    if snapshot.schema_version != REPO_MUTATION_OPLOG_SCHEMA_VERSION {
        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "unsupported repo mutation snapshot schema version",
        )));
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
            return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                "repo snapshot path must be normal",
            )));
        };
        // A file name outside UTF-8 keeps its bytes as a Git path's text
        // (FIX 21326), the text the pinned and tree walks give that name.
        let part = git_path_text_of_os(part)?;
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(&part);
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
        Err(Error::Code(CodeError::InvalidRepoMutationRecord(
            "symlink repo snapshots are unsupported on this platform",
        )))
    }
}
