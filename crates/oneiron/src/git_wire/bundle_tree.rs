//! Exact bundle bytes and modes staged through the existing Git bridge.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::Result;
use super::mutation_commands::{path_arg, run_git, utf8_trimmed};

static BUNDLE_BLOB_COUNTER: AtomicU64 = AtomicU64::new(1);

/// One entry of a bundle's tree change: its path, its exact new
/// bytes (`None` removes it) and its Git mode once present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BundleTreeEdit {
    pub(crate) path: String,
    pub(crate) content: Option<Vec<u8>>,
    pub(crate) mode: u32,
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

