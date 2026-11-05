//! Exact bundle bytes and modes staged through the existing Git bridge.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use super::mutation_commands::{path_arg, run_git, utf8_trimmed};
use crate::error::{Error, Result};
use crate::git_wire::GitOid;
use crate::store::code_tree_blob::MODE_GITLINK;

static BUNDLE_BLOB_COUNTER: AtomicU64 = AtomicU64::new(1);

/// One entry of a bundle's tree change: its path, its exact new
/// bytes (`None` removes it) and its Git mode once present. For a gitlink,
/// the bytes are its OID, not content from the linked repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BundleTreeEdit {
    pub(crate) path: String,
    pub(crate) content: Option<Vec<u8>>,
    pub(crate) mode: u32,
}

/// Opaque gitlinks in the current index, without opening their repositories.
pub(crate) fn gitlink_index_entries(root: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let raw = run_git(
        root,
        &["ls-files".to_owned(), "--stage".to_owned(), "-z".to_owned()],
    )?;
    let mut links = BTreeMap::new();
    for entry in raw
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let mut parts = entry.splitn(2, |byte| *byte == b'\t');
        let header = std::str::from_utf8(parts.next().unwrap_or_default())
            .map_err(|_| Error::InvalidClaimBody("Git index header must be UTF-8"))?;
        let mut fields = header.split(' ');
        if fields.next() != Some("160000") {
            continue;
        }
        let oid = fields
            .next()
            .ok_or(Error::InvalidClaimBody("gitlink index OID missing"))?;
        if fields.next() != Some("0") {
            return Err(Error::ConcurrentWrite(
                "Git index holds an unresolved gitlink",
            ));
        }
        let path = std::str::from_utf8(
            parts
                .next()
                .ok_or(Error::InvalidClaimBody("gitlink index path missing"))?,
        )
        .map_err(|_| Error::InvalidClaimBody("gitlink index path must be UTF-8"))?;
        links.insert(
            path.to_owned(),
            GitOid::parse_hex(oid)?.as_str().as_bytes().to_vec(),
        );
    }
    Ok(links)
}

/// Gitlink paths in an outer tree, without opening any linked commit.
pub(crate) fn gitlink_paths_at(
    root: &Path,
    revision: &str,
) -> Result<std::collections::BTreeSet<String>> {
    let raw = run_git(
        root,
        &[
            "ls-tree".to_owned(),
            "-r".to_owned(),
            "-z".to_owned(),
            revision.to_owned(),
        ],
    )?;
    let mut paths = std::collections::BTreeSet::new();
    for entry in raw
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let mut parts = entry.splitn(2, |byte| *byte == b'\t');
        let header = parts.next().unwrap_or_default();
        if !header.starts_with(b"160000 ") {
            continue;
        }
        let path = std::str::from_utf8(
            parts
                .next()
                .ok_or(Error::InvalidClaimBody("gitlink tree path missing"))?,
        )
        .map_err(|_| Error::InvalidClaimBody("gitlink tree path must be UTF-8"))?;
        paths.insert(path.to_owned());
    }
    Ok(paths)
}

fn gitlink_oid(content: &[u8]) -> Result<String> {
    let oid = std::str::from_utf8(content)
        .map_err(|_| Error::InvalidClaimBody("gitlink OID must be UTF-8"))?;
    Ok(GitOid::parse_hex(oid)?.as_str().to_owned())
}

/// Applies `edits` to the index of the checkout at `root`, and, when
/// `checkout`, writes each entry into its working tree through Git: a
/// regular removal leaves the index and the tree, and a blob is hashed
/// exactly (no filters). Gitlinks change only the index: no linked
/// repository is read, removed or checked out. No symlink is followed.
///
/// # Errors
/// A Git failure, or a temporary blob file that cannot be written.
pub(crate) fn stage_bundle_tree_edits(
    root: &Path,
    edits: &[BundleTreeEdit],
    checkout: bool,
) -> Result<()> {
    let gitlinks = gitlink_index_entries(root)?;
    if checkout
        && edits.iter().any(|edit| {
            edit.content.is_some()
                && edit.mode != MODE_GITLINK
                && gitlinks.keys().any(|parent| {
                    edit.path
                        .strip_prefix(parent.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
                })
        })
    {
        return Err(Error::InvalidClaimBody(
            "a bundle cannot check out inside a linked repository",
        ));
    }
    for edit in edits {
        let path = edit.path.clone();
        let Some(content) = &edit.content else {
            if gitlinks.contains_key(&path) {
                run_git(
                    root,
                    &[
                        "update-index".to_owned(),
                        "--force-remove".to_owned(),
                        "--".to_owned(),
                        path,
                    ],
                )?;
                continue;
            }
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
        let oid = if edit.mode == MODE_GITLINK {
            gitlink_oid(content)?
        } else {
            hash_blob(root, content)?
        };
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
        if checkout && edit.mode != MODE_GITLINK {
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
