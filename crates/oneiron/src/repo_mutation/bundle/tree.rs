//! A file bundle's exact tree change (G4 PR2; moved here from
//! `received_file/tree.rs` under bundle names, FIX 10928): every entry a
//! received or native bundle removes, adds or changes, with its exact bytes
//! and Git mode, applied through the index, never by writing through a
//! link. One staged commit carries the whole bundle; the live checkout
//! moves to it by a two-tree read, then its HEAD by compare-and-swap,
//! exactly as a reviewed file write does.
use std::path::Path;

use super::super::git::{run_git, validate_relative_repo_path};
use super::super::proposal::{RepoProposedFile, invalid};
use super::super::queue::PreparedCommitFile;
use super::super::snapshot::{SnapshotCustody, StoredRepoSnapshot, encode_snapshot};
use super::super::support::utf8_trimmed;
use super::super::types::RepoForkHash;
use super::super::worktree::{create_queue_worktree, remove_queue_worktree};
use crate::error::{Error, Result};

/// A symlink's Git mode; its bytes are its target text.
const MODE_SYMLINK: u32 = 0o120_000;
/// An executable regular file's Git mode.
const MODE_EXECUTABLE: u32 = 0o100_755;

pub(crate) use crate::git_wire::bundle_tree::BundleTreeEdit;

/// The tree change a bundle's files make: removals first, then
/// additions, so a file/directory transition never finds its way blocked.
///
/// # Errors
/// A file with no reviewed state change, a present file with no mode, or
/// bytes that disagree with the reviewed presence.
pub(crate) fn bundle_tree_edits(files: &[RepoProposedFile]) -> Result<Vec<BundleTreeEdit>> {
    let mut edits = Vec::with_capacity(files.len());
    for file in files {
        validate_relative_repo_path(&file.path)?;
        let state = file
            .metadata_edit
            .as_ref()
            .ok_or(invalid("a received file carries its reviewed state change"))?;
        let mode = match (&file.content, state.replacement.mode) {
            (Some(_), Some(mode)) => mode,
            (None, None) => 0,
            _ => {
                return Err(invalid(
                    "received bytes disagree with their reviewed presence",
                ));
            }
        };
        edits.push(BundleTreeEdit {
            path: file.path.clone(),
            content: file.content.clone(),
            mode,
        });
    }
    edits.sort_by(|left, right| {
        (left.content.is_some(), &left.path).cmp(&(right.content.is_some(), &right.path))
    });
    Ok(edits)
}

pub(crate) use crate::git_wire::bundle_tree::stage_bundle_tree_edits;

/// Stages the whole bundle as ONE commit on the checkout's HEAD, in a
/// queue-owned worktree, before any row is written.
///
/// # Errors
/// A Git failure; the worktree is removed.
pub(in crate::repo_mutation) fn prepare_bundle_files_commit(
    repo_root: &Path,
    edits: &[BundleTreeEdit],
    message: &str,
) -> Result<PreparedCommitFile> {
    let head = |root: &Path| -> Result<String> {
        utf8_trimmed(
            run_git(
                root,
                &[
                    "rev-parse".to_owned(),
                    "--verify".to_owned(),
                    "HEAD".to_owned(),
                ],
            )?,
            "git HEAD must be UTF-8",
        )
    };
    let base_head = head(repo_root)?;
    let worktree_path = create_queue_worktree(repo_root)?;
    let preparation = (|| -> Result<PreparedCommitFile> {
        stage_bundle_tree_edits(&worktree_path, edits, false)?;
        run_git(
            &worktree_path,
            &[
                "-c".to_owned(),
                "user.name=Oneiron".to_owned(),
                "-c".to_owned(),
                "user.email=oneiron@example.invalid".to_owned(),
                "commit".to_owned(),
                "-q".to_owned(),
                "-m".to_owned(),
                message.to_owned(),
            ],
        )?;
        Ok(PreparedCommitFile {
            worktree_path: worktree_path.clone(),
            base_head: base_head.clone(),
            new_head: head(&worktree_path)?,
        })
    })();
    if preparation.is_err() {
        let _ = remove_queue_worktree(repo_root, &worktree_path);
    }
    preparation
}

/// Moves the live checkout to the prepared commit: its index and tree by
/// a two-tree read from the base, then its HEAD by compare-and-swap.
///
/// # Errors
/// A Git failure, a checkout that is not at its base included.
pub(in crate::repo_mutation) fn apply_prepared_bundle_files(
    repo_root: &Path,
    prepared: &PreparedCommitFile,
) -> Result<()> {
    run_git(
        repo_root,
        &[
            "read-tree".to_owned(),
            "-m".to_owned(),
            "-u".to_owned(),
            prepared.base_head.clone(),
            prepared.new_head.clone(),
        ],
    )?;
    run_git(
        repo_root,
        &[
            "update-ref".to_owned(),
            "HEAD".to_owned(),
            prepared.new_head.clone(),
            prepared.base_head.clone(),
        ],
    )?;
    Ok(())
}

/// The fork hash the checkout has once the bundle lands on `pre`: every
/// edited entry replaced as custody keeps it, symlinks as their targets.
///
/// # Errors
/// A symlink target that is not UTF-8, or an encoding failure.
pub(in crate::repo_mutation) fn bundle_post_snapshot(
    custody: &SnapshotCustody,
    pre: &StoredRepoSnapshot,
    edits: &[BundleTreeEdit],
    new_head: &str,
) -> Result<RepoForkHash> {
    let mut post = pre.clone();
    post.head = Some(new_head.to_owned());
    for edit in edits {
        post.entries.retain(|entry| entry.path != edit.path);
        let Some(content) = &edit.content else {
            continue;
        };
        // A symlink's target is kept under custody as the captured
        // checkout keeps it (FIX 8840), so the hashes agree.
        post.entries.push(if edit.mode == MODE_SYMLINK {
            custody.symlink(
                edit.path.clone(),
                String::from_utf8(content.clone())
                    .map_err(|_| Error::InvalidClaimBody("symlink target must be UTF-8"))?,
            )
        } else {
            custody.file(
                edit.path.clone(),
                edit.mode == MODE_EXECUTABLE,
                content.clone(),
            )
        });
    }
    post.entries
        .sort_by(|left, right| left.path.cmp(&right.path));
    Ok(*blake3::hash(&encode_snapshot(&post)?).as_bytes())
}
