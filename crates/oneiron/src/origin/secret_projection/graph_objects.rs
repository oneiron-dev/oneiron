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
    /// The byte path a recipient copy's tree or blob occurs at.
    pub(crate) occurrence: Option<Vec<u8>>,
}

/// One place a changed object occurs in a changed parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoProjectedLink {
    pub(crate) parent: GitOid,
    pub(crate) parent_occurrence: Option<Vec<u8>>,
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
    changed: HashMap<ObjectKey, GitOid>,
}

/// One object as the walk keys it: its id, and a recipient copy's byte
/// path for a tree or blob on a released path.
type ObjectKey = (GitOid, Option<Vec<u8>>);

/// The released files of a recipient copy, each its exact byte path and
/// ORIGINAL blob; a masked copy has none.
pub(crate) type RepoProjectionRelease = BTreeSet<(Vec<u8>, GitOid)>;

impl RepoProjectionCopy {
    /// The copy id of the root `original` (a commit or tag, which is never
    /// keyed by a path): its own id when nothing it reaches changed.
    pub(crate) fn copy_of(&self, original: &GitOid) -> GitOid {
        self.changed
            .get(&(original.clone(), None))
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
    occurrence: Option<Vec<u8>>,
    edges: Vec<GitObjectEdge>,
    next: usize,
}

impl Frame {
    fn key(&self) -> ObjectKey {
        (self.original.clone(), self.occurrence.clone())
    }
}

/// Copies the closure of `tips` from `canonical` into `copy_store`, every
/// object children first, each marked blob masked and each object above a
/// changed one re-encoded (module docs). `release` names a recipient
/// copy's released files; `None` is the masked copy.
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
    release: Option<&RepoProjectionRelease>,
) -> Result<RepoProjectionCopy> {
    let mut copy = RepoProjectionCopy::default();
    let mut copied: HashSet<ObjectKey> = HashSet::new();
    let walk = Walk {
        vault,
        wire,
        canonical,
        copy_store,
        facts,
        store_id,
        release,
    };
    for tip in tips {
        let root = (tip.clone(), None);
        if copied.contains(&root) {
            continue;
        }
        let mut walking: HashSet<ObjectKey> = HashSet::from([root]);
        let mut frames = vec![frame(wire, canonical, tip, None)?];
        while let Some(top) = frames.last_mut() {
            if let Some(edge) = top.edges.get(top.next) {
                let child = edge.target().clone();
                let occurrence = child_occurrence(release, top.occurrence.as_deref(), edge);
                top.next += 1;
                let key = (child.clone(), occurrence.clone());
                if copied.contains(&key) {
                    continue;
                }
                if !walking.insert(key) {
                    return Err(Error::InvariantViolation("a git object graph loops"));
                }
                frames.push(frame(wire, canonical, &child, occurrence)?);
                continue;
            }
            let Some(done) = frames.pop() else {
                break;
            };
            let key = done.key();
            walking.remove(&key);
            walk.copy_one(done, &mut copy)?;
            copied.insert(key);
        }
    }
    Ok(copy)
}

/// What one closure copy reads from and writes to.
struct Walk<'a, 'w> {
    vault: &'a Vault,
    wire: &'a GitWire<'w>,
    canonical: &'a GitWireRepo,
    copy_store: &'a GitWireRepo,
    facts: &'a RepoMarkFacts,
    store_id: EntityId,
    release: Option<&'a RepoProjectionRelease>,
}

/// A walk level for `original` at `occurrence`: what it names, its bytes
/// dropped.
fn frame(
    wire: &GitWire<'_>,
    canonical: &GitWireRepo,
    original: &GitOid,
    occurrence: Option<Vec<u8>>,
) -> Result<Frame> {
    let object = wire.read_object_to_spool(canonical, original)?;
    Ok(Frame {
        original: original.clone(),
        occurrence,
        edges: git_object_edges(&object)?,
        next: 0,
    })
}

/// The byte path the child `edge` names occurs at in a recipient copy:
/// a commit's tree at the root, a tree entry below a keyed tree at its
/// joined path, each only while a released file lies at or below it. A
/// parent commit, a tag's target and everything in a masked copy have
/// none.
fn child_occurrence(
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

impl Walk<'_, '_> {
    /// Copies one object whose every child is already copied, and records
    /// it.
    fn copy_one(&self, done: Frame, copy: &mut RepoProjectionCopy) -> Result<()> {
        let object = self
            .wire
            .read_object_to_spool(self.canonical, &done.original)?;
        let children: Vec<(&GitObjectEdge, ObjectKey)> = done
            .edges
            .iter()
            .map(|edge| {
                let occurrence = child_occurrence(self.release, done.occurrence.as_deref(), edge);
                (edge, (edge.target().clone(), occurrence))
            })
            .collect();
        let (payload, marks) = match (object.kind(), &done.occurrence) {
            (GitObjectKind::Blob, Some(path))
                if self.release.is_some_and(|release| {
                    release.contains(&(path.clone(), done.original.clone()))
                }) =>
            {
                (self.wire.project_blob(&object, None)?, Vec::new())
            }
            (GitObjectKind::Blob, _) => {
                project_blob(self.vault, self.wire, self.facts, self.store_id, &object)?
            }
            (GitObjectKind::Tree, Some(_)) => {
                let names: HashMap<Vec<u8>, GitOid> = children
                    .iter()
                    .filter_map(|(edge, key)| match edge {
                        GitObjectEdge::TreeEntry { name, .. } => copy
                            .changed
                            .get(key)
                            .map(|child| (name.clone(), child.clone())),
                        _ => None,
                    })
                    .collect();
                (
                    self.wire.project_tree_occurrences(&object, &names)?,
                    Vec::new(),
                )
            }
            _ => {
                let copies: HashMap<GitOid, GitOid> = children
                    .iter()
                    .filter_map(|(edge, key)| {
                        copy.changed
                            .get(key)
                            .map(|child| (edge.target().clone(), child.clone()))
                    })
                    .collect();
                (self.wire.project_structural(&object, &copies)?, Vec::new())
            }
        };
        let copy_id = self
            .wire
            .write_projection_object(self.copy_store, payload.object())?;
        if payload.changed() {
            copy.changed.insert(done.key(), copy_id.clone());
            for (edge, key) in &children {
                if let Some(child_copy) = copy.changed.get(key) {
                    copy.links.push(RepoProjectedLink {
                        parent: done.original.clone(),
                        parent_occurrence: done.occurrence.clone(),
                        place: place_of(edge),
                        child_original: edge.target().clone(),
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
            occurrence: done.occurrence,
        });
        Ok(())
    }
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
