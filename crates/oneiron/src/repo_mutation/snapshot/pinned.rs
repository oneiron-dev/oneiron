//! The pinned base a run's work opens from (FIX 6867, G1 PR2a): the tree of
//! one immutable commit, read from the object store through GitWire, never
//! from a writable checkout. Each entry keeps its mode and symlink target,
//! and snapshot custody keeps out what it keeps out of a captured checkout.
//! The base encodes as the existing [`StoredRepoSnapshot`] with the commit as
//! its head, so its hash names it as a captured snapshot's names that one.
//! A gitlink names another repository's commit and holds no file here, so it
//! is passed over, as the codebase importer passes over it. The walk names
//! each blob first and reads them all in a few batched reads (FIX 6946).

use std::collections::BTreeMap;

use super::super::git::validate_relative_repo_path;
use super::{SnapshotCustody, StoredRepoSnapshot, StoredRepoSnapshotEntryKind, encode_snapshot};
use crate::Vault;
use crate::error::{CodeError, Error, Result};
use crate::git_wire::{GitOid, GitWire, GitWireRepo};
use crate::repo_mutation::{REPO_MUTATION_OPLOG_SCHEMA_VERSION, RepoForkHash};

/// A tree entry's mode for a subtree.
const MODE_TREE: u32 = 0o040_000;
/// A tree entry's mode for a symlink.
const MODE_SYMLINK: u32 = 0o120_000;
/// A tree entry's mode for a gitlink (a submodule's commit).
const MODE_GITLINK: u32 = 0o160_000;
/// The file-type bits of a tree entry's mode.
const MODE_TYPE_MASK: u32 = 0o170_000;
/// The file-type bits of a regular file.
const MODE_REGULAR: u32 = 0o100_000;

/// One commit's tree as a run's work starts from it.
pub(crate) struct RepoPinnedBase {
    /// The hash of the encoded snapshot.
    pub(crate) fork_hash: RepoForkHash,
    /// The encoded snapshot, head = the commit, which a run's proposal
    /// retains in the snapshot family.
    pub(crate) encoded: Vec<u8>,
    /// Every regular file custody keeps, by repo-relative path.
    pub(crate) files: BTreeMap<String, Vec<u8>>,
}

impl Vault {
    /// The pinned base of `commit` in `repo`'s object store.
    ///
    /// # Errors
    /// A commit or tree GitWire cannot read, a path that is not a normal
    /// repo-relative path, an entry that is no file, directory, symlink or
    /// gitlink, or a store failure.
    pub(crate) fn capture_repo_snapshot_at_commit(
        &self,
        repo: &GitWireRepo,
        commit: &GitOid,
    ) -> Result<RepoPinnedBase> {
        let wire = GitWire::new(self)?;
        let commit = wire.resolve_commit(repo, commit.as_str())?;
        let tree = commit_tree(&wire.read_object(repo, &commit)?)?;
        let custody = SnapshotCustody::of(self, repo.repo_root())?;
        let mut walk = PinnedWalk {
            wire: &wire,
            repo,
            blobs: BTreeMap::new(),
        };
        walk.tree(&tree, "")?;
        let mut blobs = walk.blobs;
        let oids: Vec<GitOid> = blobs.keys().cloned().collect();
        let mut entries = Vec::new();
        let mut files = BTreeMap::new();
        let mut target_not_utf8 = false;
        let complete = wire.read_blobs(repo, &oids, &mut |oid, content| {
            for (path, mode) in blobs.remove(oid).unwrap_or_default() {
                if mode == MODE_SYMLINK {
                    match std::str::from_utf8(content) {
                        Ok(target) => entries.push(custody.symlink(path, target.to_owned())),
                        Err(_) => target_not_utf8 = true,
                    }
                    continue;
                }
                let kept = custody.file(path, mode & 0o111 != 0, content.to_vec());
                if kept.kind == StoredRepoSnapshotEntryKind::File {
                    files.insert(kept.path.clone(), kept.content.clone());
                }
                entries.push(kept);
            }
        })?;
        if target_not_utf8 {
            return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                "repo snapshot symlink target must be UTF-8",
            )));
        }
        if !complete || !blobs.is_empty() {
            return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                "pinned tree names a blob its object store does not hold",
            )));
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let encoded = encode_snapshot(&StoredRepoSnapshot {
            schema_version: REPO_MUTATION_OPLOG_SCHEMA_VERSION,
            head: Some(commit.as_str().to_owned()),
            entries,
        })?;
        Ok(RepoPinnedBase {
            fork_hash: *blake3::hash(&encoded).as_bytes(),
            encoded,
            files,
        })
    }
}

/// The tree a raw commit object names on its first line.
fn commit_tree(raw: &[u8]) -> Result<GitOid> {
    let first = raw.split(|byte| *byte == b'\n').next().unwrap_or_default();
    let tree = first
        .strip_prefix(b"tree ")
        .and_then(|hex| std::str::from_utf8(hex).ok())
        .ok_or(Error::Code(CodeError::InvalidRepoMutationRecord(
            "pinned commit object names no tree",
        )))?;
    GitOid::parse_hex(tree)
}

struct PinnedWalk<'w, 'v> {
    wire: &'w GitWire<'v>,
    repo: &'w GitWireRepo,
    /// Each file or symlink blob the tree names, with every path and mode
    /// that holds it, read after the walk.
    blobs: BTreeMap<GitOid, Vec<(String, u32)>>,
}

impl PinnedWalk<'_, '_> {
    fn tree(&mut self, tree: &GitOid, prefix: &str) -> Result<()> {
        for entry in self.wire.read_tree(self.repo, tree)? {
            let name = std::str::from_utf8(&entry.name).map_err(|_| {
                Error::Code(CodeError::InvalidRepoMutationRecord(
                    "repo snapshot path must be UTF-8",
                ))
            })?;
            let path = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            validate_relative_repo_path(&path)?;
            match entry.mode {
                MODE_TREE => self.tree(&entry.oid, &path)?,
                MODE_GITLINK => {}
                mode if mode == MODE_SYMLINK || mode & MODE_TYPE_MASK == MODE_REGULAR => {
                    self.blobs.entry(entry.oid).or_default().push((path, mode));
                }
                _ => {
                    return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                        "repo snapshot supports only files, directories, and symlinks",
                    )));
                }
            }
        }
        Ok(())
    }
}
