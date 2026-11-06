//! Core half of `git_wire::projected_object`: its store-layer items live in `oneiron_store::git_wire::projected_object` and are
//! re-exported here; the items below stay in the engine.

#![allow(
    dead_code,
    reason = "FIX 7608 slice 2b-i: preparation only; slice 2b-ii is the first caller"
)]

pub use oneiron_store::git_wire::projected_object::*;

use super::config::GIT_WIRE_MAX_PUBLICATIONS;
use super::failure::{classify_failure, invalid};
use super::import_fetch::init_private_bare_store;
use super::repo::repo_identity_for;
use super::retained_object::{GitObjectKind, GitRetainedObject, GitSpool};
use super::wire_reads::parse_oid_output;
use super::{
    GitOid, GitRefPublication, GitWire, GitWireCommitOutcome, GitWireObjectWrite, GitWireOperation,
    GitWireRepo, GitWireResult, lock_repository,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::store::code_snapshot::RepoRef;
use std::collections::HashMap;
use std::path::Path;

impl GitWire<'_> {
    /// A blob of a masked copy: the original when `copy` is `None` or holds
    /// the original's own bytes, else `copy` sealed in a fresh spool.
    ///
    /// # Errors
    /// An IO failure.
    pub fn project_blob(
        &self,
        original: &GitRetainedObject,
        copy: Option<&[u8]>,
    ) -> GitWireResult<GitProjectedPayload> {
        let Some(copy) = copy else {
            return Ok(unchanged(original));
        };
        if *blake3::hash(copy).as_bytes() == original.content_blake3() {
            return Ok(unchanged(original));
        }
        let spool = GitSpool::pump(self.spool_dir(), copy)?;
        Ok(GitProjectedPayload {
            object: GitRetainedObject::encoded(GitObjectKind::Blob, spool),
            changed: true,
            signature_not_preserved: false,
        })
    }

    /// A tree, commit or tag of a masked copy: each object id it names
    /// replaced by its copy's in `copies` (which holds only ids that
    /// changed), and nothing else changed. With no named id in `copies`
    /// the payload is the original's own bytes.
    ///
    /// # Errors
    /// A malformed object, a blob, or an IO failure.
    pub fn project_structural(
        &self,
        original: &GitRetainedObject,
        copies: &HashMap<GitOid, GitOid>,
    ) -> GitWireResult<GitProjectedPayload> {
        let raw = original.read_bytes()?;
        let encoded = match original.kind() {
            GitObjectKind::Blob => {
                return Err(invalid("a blob has no structure to re-encode"));
            }
            GitObjectKind::Tree => encode_tree(&raw, copies)?.map(|bytes| (bytes, false)),
            GitObjectKind::Commit => encode_headed(&raw, copies, false)?,
            GitObjectKind::Tag => encode_headed(&raw, copies, true)?,
        };
        let Some((bytes, signature_dropped)) = encoded else {
            return Ok(unchanged(original));
        };
        let spool = GitSpool::pump(self.spool_dir(), bytes.as_slice())?;
        Ok(GitProjectedPayload {
            object: GitRetainedObject::encoded(original.kind(), spool),
            changed: true,
            signature_not_preserved: signature_dropped,
        })
    }

    /// A tree of a recipient copy (FIX 7608 pre-flip, FIX 9328): each entry
    /// `copies` names by its name bytes pointed at that copy, at the very
    /// id position it is stored at, and nothing else changed. One id named
    /// by two entries may so take two copies; a submodule's entry is never
    /// rewritten. With no entry rewritten the payload is the original's.
    ///
    /// # Errors
    /// A malformed tree, an object that is not a tree, or an IO failure.
    pub(crate) fn project_tree_occurrences(
        &self,
        original: &GitRetainedObject,
        copies: &HashMap<Vec<u8>, GitOid>,
    ) -> GitWireResult<GitProjectedPayload> {
        if !matches!(original.kind(), GitObjectKind::Tree) {
            return Err(invalid("only a tree is re-encoded by occurrence"));
        }
        let raw = original.read_bytes()?;
        let mut out: Option<Vec<u8>> = None;
        for entry in tree_entries(&raw)? {
            if entry.mode == GITLINK_MODE {
                continue;
            }
            let Some(copy) = copies.get(&entry.name).filter(|copy| **copy != entry.oid) else {
                continue;
            };
            let bytes = out.get_or_insert_with(|| raw.to_vec());
            bytes[entry.oid_at..entry.oid_at + RAW_OID_BYTES].copy_from_slice(&raw_oid(copy)?);
        }
        let Some(bytes) = out else {
            return Ok(unchanged(original));
        };
        let spool = GitSpool::pump(self.spool_dir(), bytes.as_slice())?;
        Ok(GitProjectedPayload {
            object: GitRetainedObject::encoded(GitObjectKind::Tree, spool),
            changed: true,
            signature_not_preserved: false,
        })
    }

    /// Makes the fresh bare store a masked copy is written into, at
    /// `root/repo.git`, and binds it for object writes and ref
    /// publications. `root` must not hold a store yet. The handle pins no
    /// commit: nothing in the store is proved until its graph is whole, and
    /// a reader opens it with `open_repo` on the copy's root afterwards.
    ///
    /// # Errors
    /// A store that cannot be made, or one that is not its own common
    /// directory or shares objects with another.
    pub(crate) fn init_projection_store(&self, root: &Path) -> GitWireResult<GitWireRepo> {
        std::fs::create_dir_all(root)?;
        let root = root.canonicalize()?;
        if root.join(PROJECTION_STORE_REPO).exists() {
            return Err(invalid("a masked copy's store already exists"));
        }
        let output = init_private_bare_store(&self.process_env, &root, PROJECTION_STORE_REPO)?;
        if !output.success {
            return Err(classify_failure(&output).error(GitWireOperation::ImportScratchInit));
        }
        let repo_root = root.join(PROJECTION_STORE_REPO).canonicalize()?;
        self.bind_projection_store(&repo_root)
    }

    /// Writes one retained object into the copy store `repo` through the
    /// ordinary object effect, its payload streamed from the spool, with no
    /// keep-ref and no wire record (FIX 9106): one Git call an object. The
    /// copy's root refs pin it once its graph is whole. An object read from
    /// a store must land at the OID it was read at.
    ///
    /// # Errors
    /// A failed write, or a copy that landed at another OID.
    pub(crate) fn write_projection_object(
        &self,
        repo: &GitWireRepo,
        object: &GitRetainedObject,
    ) -> GitWireResult<GitOid> {
        let argv = GitWireObjectWrite::Retained(object.clone()).argv()?;
        let _guard = lock_repository(&repo.common_dir)?;
        let output = self.run_mutation(repo, &argv)?;
        let oid = parse_oid_output(&output.stdout)?;
        if object.source_oid().is_some_and(|source| *source != oid) {
            return Err(invalid(
                "a retained copy of a stored object landed at another object id",
            ));
        }
        Ok(oid)
    }

    /// Publishes a fresh copy store's refs, each batch the publication
    /// bound holds through the one transactional path (whole-graph
    /// availability proved for each target). The store serves nothing until
    /// its records stand, so the batches need not be one transaction, and
    /// no count bound ends the set.
    ///
    /// # Errors
    /// A failed or refused publication.
    pub(crate) fn publish_projection_refs(
        &self,
        copy_store: &GitWireRepo,
        publications: Vec<GitRefPublication>,
        now: u64,
    ) -> GitWireResult<()> {
        for batch in publications.chunks(GIT_WIRE_MAX_PUBLICATIONS) {
            match self.publish_refs(copy_store, batch.to_vec(), now)? {
                GitWireCommitOutcome::Applied(_) | GitWireCommitOutcome::Replayed(_) => {}
                GitWireCommitOutcome::Rejected { .. } => {
                    return Err(invalid("a masked copy's fresh store refused its refs"));
                }
            }
        }
        Ok(())
    }

    /// The bare copy store at `root/repo.git`, bound for writes, or `None`
    /// when there is none.
    ///
    /// # Errors
    /// A store that is not its own common directory or shares objects.
    pub(crate) fn existing_projection_store(
        &self,
        root: &Path,
    ) -> GitWireResult<Option<GitWireRepo>> {
        let candidate = root.join(PROJECTION_STORE_REPO);
        if !candidate.exists() {
            return Ok(None);
        }
        self.bind_projection_store(&candidate.canonicalize()?)
            .map(Some)
    }

    fn bind_projection_store(&self, repo_root: &Path) -> Result<GitWireRepo> {
        let common_dir = self.canonical_common_dir(repo_root)?;
        if common_dir != repo_root {
            return Err(invalid(
                "a masked copy's store must be its own common directory",
            ));
        }
        for shared in [
            "commondir",
            "objects/info/alternates",
            "objects/info/http-alternates",
        ] {
            if common_dir.join(shared).exists() {
                return Err(invalid("a masked copy's store must not share objects"));
            }
        }
        Ok(GitWireRepo {
            repo_ref: RepoRef::LocalFolder {
                path: repo_root.to_string_lossy().into_owned(),
                commit: String::new(),
            },
            repo_root: repo_root.to_path_buf(),
            identity: repo_identity_for(&common_dir),
            common_dir,
        })
    }
}
