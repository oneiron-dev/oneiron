//! The restore of a recorded working-tree snapshot onto its checkout
//! (`restore_repo_snapshot`), with the inventory, index reset and file
//! helpers only the restore uses.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use super::super::git::{
    git_output_optional, repo_path_on_disk, run_git, validate_relative_repo_path,
};
use super::super::oplog::{SNAPSHOT, repo_mutation_snapshot_key};
use super::super::secret_remediation::commit_files;
use super::super::support::{sha256_bytes, utf8_trimmed};
use super::super::types::RepoForkHash;
use super::super::worktree::{
    create_owner_only_repo_file_no_symlink, ensure_repo_parent_dirs_no_symlink,
    write_repo_file_no_symlink,
};
use super::{
    SnapshotCustody, StoredRepoSnapshot, StoredRepoSnapshotEntry, StoredRepoSnapshotEntryKind,
    is_executable, nested_repository, repo_relative_path, require_snapshot_schema,
    snapshot_recorded_for_repo,
};
use crate::Vault;
use crate::codebase::RepoRef;
use crate::error::{CodeError, Error, Result};
use crate::git_wire::bundle_tree::{
    BundleTreeEdit, gitlink_index_entries, gitlink_paths_at, stage_bundle_tree_edits,
};
use crate::git_wire::{GitWire, git_path_string};
use crate::store::code_tree_blob::MODE_GITLINK;

/// Paths one restore's `git reset` names, under GitWire's argv bound.
const RESTORE_INDEX_PATHS_PER_CALL: usize = 56;

pub(in crate::repo_mutation) fn restore_repo_snapshot(
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
    let lifted = super::super::lift::lifted_entries_in_txn(vault, &rtxn, &key, &raw)?;
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

    // A withheld file the checkout no longer holds comes back from the
    // snapshot head's own commit (FIX 2230). One at or inside a linked
    // checkout stays as it is, and its bytes are never read: the restore
    // never writes into one.
    let in_linked_checkout = |path: &str| {
        linked_paths.iter().chain(&residual_paths).any(|linked| {
            path == linked
                || path
                    .strip_prefix(linked.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    };
    let mut recreated = withheld_files_to_recreate(
        vault,
        repo_ref,
        repo_root,
        &snapshot,
        &lifted,
        in_linked_checkout,
    )?;

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
            if let Some(content) = recreated.remove(&entry.path) {
                create_owner_only_repo_file_no_symlink(
                    repo_root,
                    &entry.path,
                    &content,
                    entry.executable,
                )?;
                changed.insert(entry.path);
            }
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

/// The bytes the snapshot head commits at each withheld path the checkout
/// no longer holds, which the restore writes anew (FIX 2230). The vault keeps
/// no byte of a withheld file (OF-067), so the repository's own object store
/// is the one source: a path that commit tracks as a regular file whose bytes
/// custody still withholds comes back as those bytes, and recaptures as the
/// snapshot's own entry. Any other gone withheld file stays gone:
/// - a path custody declares is vault-resident, and a T2 file there
///   re-materializes from the vault alone under its lease, never from a
///   snapshot or a commit (ARCH-0069 S4), so a lease that expired stays torn
///   down;
/// - a path `skip` names (one at or inside a linked checkout), whose bytes
///   are not read either;
/// - every path off Unix, where no file is owner-only from its first byte.
///
/// A withheld file the checkout still holds keeps its bytes and its
/// permissions, which may be owner-only. The commit is read at the snapshot
/// head, whatever revision the caller's `repo_ref` pins. A head commit, or a
/// path's blob, that the object store no longer holds (a gc after a reset, a
/// shallow or partial clone) recreates nothing at that path, and the restore
/// goes on: it writes every other entry, and the post-check reports the file
/// (review 2 of FIX 2230, P3-1).
fn withheld_files_to_recreate(
    vault: &Vault,
    repo_ref: &RepoRef,
    repo_root: &Path,
    snapshot: &StoredRepoSnapshot,
    lifted: &BTreeSet<String>,
    skip: impl Fn(&str) -> bool,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let Some(head) = snapshot.head.as_deref() else {
        return Ok(BTreeMap::new());
    };
    if !cfg!(unix) {
        return Ok(BTreeMap::new());
    }
    let custody = SnapshotCustody::of(vault, repo_root)?;
    let mut gone = BTreeSet::new();
    for entry in &snapshot.entries {
        let withheld =
            entry.kind == StoredRepoSnapshotEntryKind::Withheld || lifted.contains(&entry.path);
        if !withheld || skip(&entry.path) || custody.declares(&entry.path) {
            continue;
        }
        if fs::symlink_metadata(repo_path_on_disk(repo_root, &entry.path)?).is_err() {
            gone.insert(entry.path.clone());
        }
    }
    if gone.is_empty() {
        return Ok(BTreeMap::new());
    }
    let at_head = match repo_ref {
        RepoRef::LocalFolder { path, .. } => RepoRef::LocalFolder {
            path: path.clone(),
            commit: head.to_owned(),
        },
        other => other.clone(),
    };
    let opened = GitWire::new(vault).and_then(|wire| {
        let repo = wire.open_repo(at_head, repo_root)?;
        let commit = wire.resolve_commit(&repo, head)?;
        Ok((wire, repo, commit))
    });
    let (wire, repo, commit) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            tracing::warn!(
                %error,
                gone = gone.len(),
                "repo restore: the snapshot head did not read, so no gone withheld file is recreated"
            );
            return Ok(BTreeMap::new());
        }
    };
    let mut recreated = BTreeMap::new();
    for path in gone {
        // One path at a time, so a lost blob keeps only its own file gone.
        let wanted = BTreeSet::from([path.clone()]);
        let mut files = match commit_files(&wire, &repo, &commit, Some(&wanted)) {
            Ok(files) => files,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "repo restore: a gone withheld file's committed bytes did not read; it stays gone"
                );
                continue;
            }
        };
        if let Some(file) = files
            .remove(&path)
            .filter(|file| custody.withholds(&path, &file.content).is_some())
        {
            recreated.insert(path, file.content);
        }
    }
    Ok(recreated)
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
