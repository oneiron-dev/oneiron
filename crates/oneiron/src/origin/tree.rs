//! Byte-preserving projection of complete Git trees. No worktree IO or ref writes.
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitWire, GitWireRepo};
use crate::scan_check::{EngineScan, ScanCount};
use std::collections::BTreeMap;

/// One file's bytes a tree read holds in memory: a machine floor.
const MAX_TREE_FILE_BYTES: usize = 32 * 1024 * 1024;
/// One tree's file bytes a read holds in memory at once: a machine floor.
const MAX_TREE_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginTreeFile {
    pub mode: u32,
    pub content: Vec<u8>,
}
/// Reads committed bytes, including symlink targets without following links.
/// The walk reads every tree and file however many (rule 5): past its scan
/// row it raises a check and reads on; only the byte floors stop it.
pub fn read_tree_files(
    git: &GitWire<'_>,
    repo: &GitWireRepo,
    tree: &GitOid,
) -> Result<BTreeMap<String, OriginTreeFile>> {
    let mut count = start_tree_count(git, repo)?;
    let mut files = BTreeMap::new();
    let mut pending = vec![(String::new(), tree.clone())];
    let mut bytes = 0_usize;
    while let Some((prefix, oid)) = pending.pop() {
        for entry in git.read_tree(repo, &oid)? {
            count.row();
            let name = String::from_utf8(entry.name)
                .map_err(|_| Error::InvariantViolation("code paths must be UTF-8"))?;
            if name.is_empty() || name.contains('/') || matches!(name.as_str(), "." | ".." | ".git")
            {
                return Err(Error::InvariantViolation("unsafe code tree path"));
            }
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if entry.mode == 0o040000 {
                pending.push((path, entry.oid));
            } else if matches!(entry.mode, 0o100644 | 0o100755 | 0o120000 | 0o160000) {
                let content = if entry.mode == 0o160000 {
                    entry.oid.as_str().as_bytes().to_vec()
                } else {
                    git.read_object(repo, &entry.oid)?
                };
                bytes = bytes
                    .checked_add(content.len())
                    .ok_or(Error::ArithmeticOverflow("origin bytes"))?;
                if content.len() > MAX_TREE_FILE_BYTES || bytes > MAX_TREE_BYTES {
                    return Err(Error::IndexOverflow("origin file bytes"));
                }
                if files
                    .insert(
                        path,
                        OriginTreeFile {
                            mode: entry.mode,
                            content,
                        },
                    )
                    .is_some()
                {
                    return Err(Error::InvariantViolation("duplicate origin path"));
                }
            } else {
                return Err(Error::InvariantViolation("unsupported code tree mode"));
            }
        }
    }
    count.finish(git.vault());
    Ok(files)
}

/// Starts the count of one full-tree walk of `repo` against its scan row
/// (FIX 9692, 9996). The caller holds no read transaction.
pub(crate) fn start_tree_count(git: &GitWire<'_>, repo: &GitWireRepo) -> Result<ScanCount> {
    let vault = git.vault();
    let rtxn = vault.store.env.read_txn()?;
    ScanCount::start(
        &vault.store,
        &rtxn,
        EngineScan::OriginTreeEntries,
        repo.identity().as_hex().as_bytes(),
    )
}
