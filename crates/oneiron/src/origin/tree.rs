//! Bounded, byte-preserving projection of Git trees. No worktree IO or ref writes.
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitWire, GitWireRepo};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginTreeFile {
    pub mode: u32,
    pub content: Vec<u8>,
}
/// Reads committed bytes, including symlink targets without following links.
pub fn read_tree_files(
    git: &GitWire<'_>,
    repo: &GitWireRepo,
    tree: &GitOid,
) -> Result<BTreeMap<String, OriginTreeFile>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![(String::new(), tree.clone(), 0_usize)];
    let mut bytes = 0_usize;
    while let Some((prefix, oid, depth)) = pending.pop() {
        if depth > 128 {
            return Err(Error::IndexOverflow("origin tree depth"));
        }
        for entry in git.read_tree(repo, &oid)? {
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
                pending.push((path, entry.oid, depth + 1));
                if pending.len() > 100_000 {
                    return Err(Error::IndexOverflow("origin trees"));
                }
            } else if matches!(entry.mode, 0o100644 | 0o100755 | 0o120000 | 0o160000) {
                let content = if entry.mode == 0o160000 {
                    entry.oid.as_str().as_bytes().to_vec()
                } else {
                    git.read_object(repo, &entry.oid)?
                };
                bytes = bytes
                    .checked_add(content.len())
                    .ok_or(Error::ArithmeticOverflow("origin bytes"))?;
                if content.len() > 32 * 1024 * 1024
                    || bytes > 128 * 1024 * 1024
                    || files.len() >= 100_000
                {
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
    Ok(files)
}
