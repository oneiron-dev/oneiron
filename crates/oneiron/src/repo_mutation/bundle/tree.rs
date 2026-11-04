//! A file bundle's exact tree change (G4 PR2; moved here from
//! `received_file/tree.rs` under bundle names, FIX 10928): every entry a
//! received or native bundle removes, adds or changes, with its exact bytes
//! and Git mode, applied through the index, never by writing through a
//! link. One staged commit carries the whole bundle; the live checkout
//! moves to it by a two-tree read, then its HEAD by compare-and-swap,
//! exactly as a reviewed file write does.
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use super::super::git::{run_git, validate_relative_repo_path};
use super::super::proposal::{RepoProposedFile, invalid};
use super::super::queue::PreparedCommitFile;
use super::super::snapshot::{SnapshotCustody, StoredRepoSnapshot, encode_snapshot};
use super::super::support::{path_arg, utf8_trimmed};
use super::super::types::RepoForkHash;
use super::super::worktree::{create_queue_worktree, remove_queue_worktree};
use crate::error::{Error, Result};

/// A symlink's Git mode; its bytes are its target text.
const MODE_SYMLINK: u32 = 0o120_000;
/// An executable regular file's Git mode.
const MODE_EXECUTABLE: u32 = 0o100_755;

static BUNDLE_BLOB_COUNTER: AtomicU64 = AtomicU64::new(1);

/// One entry of a bundle's tree change: its path, its exact new
/// bytes (`None` removes it) and its Git mode once present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BundleTreeEdit {
    pub(crate) path: String,
    pub(crate) content: Option<Vec<u8>>,
    pub(crate) mode: u32,
}

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

/// Applies `edits` to the index of the checkout at `root`, and, when
/// `checkout`, writes each entry into its working tree through Git: a
/// removal leaves the index and the tree, an addition is hashed exactly
/// (no filters) and checked out at its mode. Nothing is read or written
/// through a symlink.
///
/// # Errors
/// A Git failure, or a temporary blob file that cannot be written.
pub(crate) fn stage_bundle_tree_edits(
    root: &Path,
    edits: &[BundleTreeEdit],
    checkout: bool,
) -> Result<()> {
    for edit in edits {
        let path = edit.path.clone();
        let Some(content) = &edit.content else {
            let mut args = vec!["rm".to_owned(), "-q".to_owned()];
            if checkout {
                args.push("-f".to_owned());
            } else {
                args.push("--cached".to_owned());
            }
            args.extend(["--".to_owned(), path]);
            run_git(root, &args)?;
            continue;
        };
        let oid = hash_blob(root, content)?;
        run_git(
            root,
            &[
                "update-index".to_owned(),
                "--add".to_owned(),
                "--replace".to_owned(),
                "--cacheinfo".to_owned(),
                format!("{:o},{oid},{path}", edit.mode),
            ],
        )?;
        if checkout {
            // A file replacing a directory whose files this bundle removed
            // can meet that directory left empty: it goes first (FIX 7539).
            if let Some(directory) = empty_directory_in_tree(root, &path)? {
                std::fs::remove_dir(directory)?;
            }
            run_git(
                root,
                &[
                    "checkout-index".to_owned(),
                    "-f".to_owned(),
                    "--".to_owned(),
                    path,
                ],
            )?;
        }
    }
    Ok(())
}

/// The empty directory standing at `path` in the working tree at `root`,
/// reached through no symlink; `None` for anything else, which Git's own
/// checkout judges.
fn empty_directory_in_tree(root: &Path, path: &str) -> Result<Option<std::path::PathBuf>> {
    let mut at = root.to_path_buf();
    for part in path.split('/') {
        at.push(part);
        match std::fs::symlink_metadata(&at) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) | Err(_) => return Ok(None),
        }
    }
    Ok(std::fs::read_dir(&at)?.next().is_none().then_some(at))
}

/// Writes `content` as a blob of the repository at `root`, exactly: no
/// clean filter or line-ending conversion. Answers its object id.
fn hash_blob(root: &Path, content: &[u8]) -> Result<String> {
    let file = std::env::temp_dir().join(format!(
        "oneiron-received-blob-{}-{}",
        std::process::id(),
        BUNDLE_BLOB_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&file, content)?;
    let hashed = run_git(
        root,
        &[
            "hash-object".to_owned(),
            "-w".to_owned(),
            "--no-filters".to_owned(),
            "--".to_owned(),
            path_arg(&file)?,
        ],
    );
    let _ = std::fs::remove_file(&file);
    utf8_trimmed(hashed?, "git blob id must be UTF-8")
}

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
