//! The copy of a masked Git graph's object closure (FIX 7608 slice 2b-i):
//! every object the roots reach, written into the copy store children
//! first, so each tree, commit and tag is re-encoded only once every object
//! it names has its copy id.
//!
//! The walk keeps its pending levels on a heap stack (an object id, what it
//! names, how far it got), never in call frames, and holds no object's
//! bytes while it waits: a history of any depth or width is copied, with no
//! object, history, byte, count or time bound (Rule 5). An object the
//! canonical store lacks ends the copy with an error: a copy never stands
//! on part of the graph. A submodule's commit lives in another repository
//! and is named as it is, never followed.
//!
//! A blob is masked when a readable mark names it: by its address in this
//! store, else by its whole bytes' BLAKE3 in any store (the same bytes are
//! the same blob). Opaque residue gives the sealed-file placeholder without
//! a byte read; span marks give the 2a masked copy, which falls to the
//! placeholder when it does not rebuild clean. Every other object keeps its
//! payload (CALL P2), so the copy store holds it at its original id.
//!
//! A recipient copy (FIX 9328, CALL GIT-REVEAL-OCCURRENCES) walks the same
//! heap stack with each tree and blob keyed by the exact byte path it
//! occurs at, but only along the paths that lead to a released file: a
//! released file's blob keeps its stored bytes at exactly its path, every
//! other marked blob is masked as in the masked copy, and a tree above a
//! released file is re-encoded per occurrence, so one tree or blob shared
//! by two paths may have two copies. Commits and tags, and every subtree
//! no released path runs through, keep the masked copy's object-id keys.

#![allow(
    dead_code,
    reason = "FIX 7608 slice 2b-i: preparation only; slice 2b-ii is the first caller"
)]

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::git_wire::ids::GitOid;
use crate::git_wire::projected_object::GitObjectEdge;
use crate::git_wire::projected_object::GitProjectedPayload;
use crate::git_wire::projected_object::git_object_edges;
use crate::git_wire::repo::GitWireRepo;
use crate::git_wire::retained_object::GitObjectKind;
use crate::git_wire::retained_object::GitRetainedObject;
use crate::origin::secret_projection::types::REPO_OPAQUE_FILE_BYTES;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// One copied object: its original id, its copy's, and what changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoProjectedObject {
    pub original: GitOid,
    pub copy: GitOid,
    pub kind: GitObjectKind,
    pub signature_not_preserved: bool,
    /// The marks a blob's copy masks, sorted; none for any other object.
    pub marks: Vec<EntityId>,
    /// The byte path a recipient copy's tree or blob occurs at.
    pub occurrence: Option<Vec<u8>>,
}

/// One object as the walk keys it: its id, and a recipient copy's byte
/// path for a tree or blob on a released path.
pub type ObjectKey = (GitOid, Option<Vec<u8>>);

/// The released files of a recipient copy, each its exact byte path and
/// ORIGINAL blob; a masked copy has none.
pub type RepoProjectionRelease = BTreeSet<(Vec<u8>, GitOid)>;

/// One pending level of the walk: an object, what it names, and how many
/// of those are done.
pub struct Frame {
    pub original: GitOid,
    pub occurrence: Option<Vec<u8>>,
    pub edges: Vec<GitObjectEdge>,
    pub next: usize,
}

impl Frame {
    pub fn key(&self) -> ObjectKey {
        (self.original.clone(), self.occurrence.clone())
    }
}

/// The byte path the child `edge` names occurs at in a recipient copy:
/// a commit's tree at the root, a tree entry below a keyed tree at its
/// joined path, each only while a released file lies at or below it. A
/// parent commit, a tag's target and everything in a masked copy have
/// none.
pub fn child_occurrence(
    release: Option<&RepoProjectionRelease>,
    parent: Option<&[u8]>,
    edge: &GitObjectEdge,
) -> Option<Vec<u8>> {
    let release = release?;
    let path = match edge {
        GitObjectEdge::CommitTree(_) => Vec::new(),
        GitObjectEdge::TreeEntry { name, .. } => {
            let parent = parent?;
            let mut path = parent.to_vec();
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(name);
            path
        }
        GitObjectEdge::CommitParent { .. } | GitObjectEdge::TagTarget(_) => return None,
    };
    release
        .iter()
        .any(|(released, _)| leads_to(&path, released))
        .then_some(path)
}

/// Whether the byte path `path` is `released` itself or a directory it
/// lies under (the root, empty, leads to every path).
fn leads_to(path: &[u8], released: &[u8]) -> bool {
    path.is_empty()
        || released == path
        || (released.starts_with(path) && released.get(path.len()) == Some(&b'/'))
}
