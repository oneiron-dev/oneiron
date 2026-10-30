//! A pinned Git tree as a queue check's input (FIX 6868): read from the
//! object store through the shipped GitWire reads, never the live checkout.
use super::MergeQueue;
use super::check_inputs::{QueueCheckFile, QueueCheckTreeSource};
use crate::code_revision::CodeTreeInventory;
use crate::contract_oracle::invalid;
use crate::error::Result;
use crate::git_wire::{GitOid, GitWire, GitWireRepo};

/// Git's mode of a tree entry that is itself a tree.
const MODE_TREE: u32 = 0o040_000;
/// Git's mode of a submodule link: a commit in another repository.
const MODE_GITLINK: u32 = 0o160_000;

/// One tree of this queue's object store.
pub(super) struct PinnedTree<'a> {
    wire: GitWire<'a>,
    repo: &'a GitWireRepo,
    tree: GitOid,
}

impl MergeQueue<'_> {
    /// The pinned tree `tree` names in this queue's object store.
    pub(super) fn pinned_tree(&self, tree: &str) -> Result<PinnedTree<'_>> {
        Ok(PinnedTree {
            wire: GitWire::new(self.vault)?,
            repo: &self.repo,
            tree: GitOid::parse_hex(tree)?,
        })
    }

    /// The tree a commit of this object store names.
    pub(super) fn commit_tree(&self, commit: &str) -> Result<String> {
        let wire = GitWire::new(self.vault)?;
        let oid = wire.resolve_commit(&self.repo, commit)?;
        if oid.as_str() != commit {
            return Err(invalid("commit must be named by its full object id"));
        }
        let body = wire.read_object(&self.repo, &oid)?;
        let line = body.split(|byte| *byte == b'\n').next().unwrap_or_default();
        let hex = line
            .strip_prefix(b"tree ")
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .ok_or_else(|| invalid("commit object names no tree"))?;
        Ok(GitOid::parse_hex(hex)?.as_str().to_owned())
    }

    /// The bytes one path names in one tree, or `None` when it names no
    /// regular file there.
    pub(super) fn tree_file(&self, tree: &str, path: &str) -> Result<Option<Vec<u8>>> {
        let wire = GitWire::new(self.vault)?;
        let mut current = GitOid::parse_hex(tree)?;
        let mut parts = path.split('/').peekable();
        while let Some(part) = parts.next() {
            let Some(entry) = wire.read_tree_entry(&self.repo, &current, part)? else {
                return Ok(None);
            };
            if parts.peek().is_some() {
                if entry.mode != MODE_TREE {
                    return Ok(None);
                }
                current = entry.oid;
            } else {
                if entry.mode & 0o170_000 != 0o100_000 {
                    return Ok(None);
                }
                return Ok(Some(wire.read_object(&self.repo, &entry.oid)?));
            }
        }
        Ok(None)
    }
}

impl QueueCheckTreeSource for PinnedTree<'_> {
    /// The tree's files through the one walker the tested seal reads
    /// ([`CodeTreeInventory::entries`], FIX 7395): every level counted, in
    /// path order, submodule links left out.
    fn files(&self) -> Result<Vec<QueueCheckFile>> {
        Ok(
            CodeTreeInventory::entries(&self.wire, self.repo, &self.tree)?
                .into_iter()
                .filter(|(_, (_, mode))| *mode != MODE_GITLINK)
                .map(|(path, (oid, mode))| QueueCheckFile {
                    path: path.into_bytes(),
                    mode,
                    oid,
                })
                .collect(),
        )
    }

    fn blob(&self, oid: &str) -> Result<Vec<u8>> {
        Ok(self.wire.read_object(self.repo, &GitOid::parse_hex(oid)?)?)
    }
}
