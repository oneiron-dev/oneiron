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

#![allow(
    dead_code,
    reason = "FIX 7608 slice 2b-i: preparation only; slice 2b-ii is the first caller"
)]

use std::collections::{HashMap, HashSet};

use super::super::secret_marks::{RepoBlobAddress, RepoBlobMarks, RepoMarkFacts};
use super::claims::RepoProjectionPlace;
use super::{REPO_OPAQUE_FILE_BYTES, project_repo_bytes_in_txn};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{
    GitObjectEdge, GitObjectKind, GitOid, GitProjectedPayload, GitRetainedObject, GitWire,
    GitWireRepo, git_object_edges,
};

/// One copied object: its original id, its copy's, and what changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoProjectedObject {
    pub(crate) original: GitOid,
    pub(crate) copy: GitOid,
    pub(crate) kind: GitObjectKind,
    pub(crate) signature_not_preserved: bool,
    /// The marks a blob's copy masks, sorted; none for any other object.
    pub(crate) marks: Vec<EntityId>,
}

/// One place a changed object occurs in a changed parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoProjectedLink {
    pub(crate) parent: GitOid,
    pub(crate) place: RepoProjectionPlace,
    pub(crate) child_original: GitOid,
    pub(crate) child_copy: GitOid,
}

/// What one closure copy wrote: every object, in the order it was written,
/// and each place a changed object occurs in a changed parent.
#[derive(Debug, Default)]
pub(crate) struct RepoProjectionCopy {
    pub(crate) objects: Vec<RepoProjectedObject>,
    pub(crate) links: Vec<RepoProjectedLink>,
    changed: HashMap<GitOid, GitOid>,
}

impl RepoProjectionCopy {
    /// The copy id of `original`: its own id when nothing it reaches
    /// changed.
    pub(crate) fn copy_of(&self, original: &GitOid) -> GitOid {
        self.changed
            .get(original)
            .cloned()
            .unwrap_or_else(|| original.clone())
    }

    /// Whether any object's copy differs from its original.
    pub(crate) fn changed_any(&self) -> bool {
        !self.changed.is_empty()
    }
}

/// One pending level of the walk: an object, what it names, and how many
/// of those are done.
struct Frame {
    original: GitOid,
    edges: Vec<GitObjectEdge>,
    next: usize,
}

/// Copies the closure of `tips` from `canonical` into `copy_store`, every
/// object children first, each marked blob masked and each object above a
/// changed one re-encoded (module docs). `copy` accumulates across calls,
/// so objects already copied are not copied again.
///
/// # Errors
/// An object the canonical store lacks, a loop, a malformed object, a
/// failed write, or a mark that does not decode.
#[allow(clippy::too_many_arguments)]
pub(crate) fn copy_repo_projection_objects(
    vault: &Vault,
    wire: &GitWire<'_>,
    canonical: &GitWireRepo,
    copy_store: &GitWireRepo,
    tips: &[GitOid],
    facts: &RepoMarkFacts,
    store_id: EntityId,
    now: u64,
) -> Result<RepoProjectionCopy> {
    let mut copy = RepoProjectionCopy::default();
    let mut copied: HashSet<GitOid> = HashSet::new();
    for tip in tips {
        if copied.contains(tip) {
            continue;
        }
        let mut walking: HashSet<GitOid> = HashSet::from([tip.clone()]);
        let mut frames = vec![frame(wire, canonical, tip)?];
        while let Some(top) = frames.last_mut() {
            if let Some(edge) = top.edges.get(top.next) {
                let child = edge.target().clone();
                top.next += 1;
                if copied.contains(&child) {
                    continue;
                }
                if !walking.insert(child.clone()) {
                    return Err(Error::InvariantViolation("a git object graph loops"));
                }
                frames.push(frame(wire, canonical, &child)?);
                continue;
            }
            let Some(done) = frames.pop() else {
                break;
            };
            walking.remove(&done.original);
            let original = done.original.clone();
            copy_one(
                vault, wire, canonical, copy_store, facts, store_id, now, done, &mut copy,
            )?;
            copied.insert(original);
        }
    }
    Ok(copy)
}

/// A walk level for `original`: what it names, its bytes dropped.
fn frame(wire: &GitWire<'_>, canonical: &GitWireRepo, original: &GitOid) -> Result<Frame> {
    let object = wire.read_object_to_spool(canonical, original)?;
    Ok(Frame {
        original: original.clone(),
        edges: git_object_edges(&object)?,
        next: 0,
    })
}

/// Copies one object whose every child is already copied, and records it.
#[allow(clippy::too_many_arguments)]
fn copy_one(
    vault: &Vault,
    wire: &GitWire<'_>,
    canonical: &GitWireRepo,
    copy_store: &GitWireRepo,
    facts: &RepoMarkFacts,
    store_id: EntityId,
    now: u64,
    done: Frame,
    copy: &mut RepoProjectionCopy,
) -> Result<()> {
    let object = wire.read_object_to_spool(canonical, &done.original)?;
    let (payload, marks) = match object.kind() {
        GitObjectKind::Blob => project_blob(vault, wire, facts, store_id, &object)?,
        _ => (wire.project_structural(&object, &copy.changed)?, Vec::new()),
    };
    let copy_id = wire.write_retained_object(copy_store, payload.object(), now)?;
    if payload.changed() {
        copy.changed.insert(done.original.clone(), copy_id.clone());
        for edge in &done.edges {
            let child = edge.target();
            if let Some(child_copy) = copy.changed.get(child) {
                copy.links.push(RepoProjectedLink {
                    parent: done.original.clone(),
                    place: place_of(edge),
                    child_original: child.clone(),
                    child_copy: child_copy.clone(),
                });
            }
        }
    }
    copy.objects.push(RepoProjectedObject {
        original: done.original,
        copy: copy_id,
        kind: object.kind(),
        signature_not_preserved: payload.signature_not_preserved(),
        marks,
    });
    Ok(())
}

/// A blob's copy: masked when a readable mark names it, else its payload.
fn project_blob(
    vault: &Vault,
    wire: &GitWire<'_>,
    facts: &RepoMarkFacts,
    store_id: EntityId,
    object: &GitRetainedObject,
) -> Result<(GitProjectedPayload, Vec<EntityId>)> {
    let marks = blob_marks(facts, store_id, object);
    if marks.is_empty() {
        return Ok((wire.project_blob(object, None)?, Vec::new()));
    }
    let bytes = if marks.opaque() {
        REPO_OPAQUE_FILE_BYTES.to_vec()
    } else {
        let txn = vault.store.env.read_txn()?;
        project_repo_bytes_in_txn(vault, &txn, &marks, object.read_bytes()?)?.into_bytes()
    };
    Ok((
        wire.project_blob(object, Some(bytes.as_slice()))?,
        marks.ids()?,
    ))
}

/// The readable marks of one blob: by its address in this store, else by
/// its whole bytes in any store.
fn blob_marks(
    facts: &RepoMarkFacts,
    store_id: EntityId,
    object: &GitRetainedObject,
) -> RepoBlobMarks {
    let addressed = object.source_oid().map(|blob| {
        facts.for_blob(&RepoBlobAddress {
            store: store_id,
            blob: blob.clone(),
        })
    });
    match addressed {
        Some(marks) if !marks.is_empty() => marks,
        _ => facts.for_hash(&object.content_blake3()),
    }
}

fn place_of(edge: &GitObjectEdge) -> RepoProjectionPlace {
    match edge {
        GitObjectEdge::TreeEntry { mode, name, .. } => RepoProjectionPlace::TreeEntry {
            mode: *mode,
            name: name.clone(),
        },
        GitObjectEdge::CommitTree(_) => RepoProjectionPlace::CommitTree,
        GitObjectEdge::CommitParent { index, .. } => {
            RepoProjectionPlace::CommitParent { index: *index }
        }
        GitObjectEdge::TagTarget(_) => RepoProjectionPlace::TagTarget,
    }
}
