//! The marks a masked Git copy is bound to (FIX 9105): the readable marks
//! naming a blob of its closure, in any store, and never the rest. Its
//! graph record names them; it is admitted again while exactly those still
//! name its closure's blobs, read from its own object records, so a mark
//! on another blob or store keeps every unrelated copy standing.

use std::collections::HashSet;

use heed::RoTxn;

use super::super::claims::{RepoProjectionAudience, RepoProjectionClaim, RepoProjectionRecord};
use super::super::graph_objects::RepoProjectionCopy;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::git_wire::{GitObjectKind, GitOid};
use crate::origin::secret_marks::RepoMarkFacts;

/// `record`, a graph record, made under `marks` for `audience`.
pub(super) fn graph_record_with(
    record: &RepoProjectionRecord,
    marks: Vec<EntityId>,
    audience: RepoProjectionAudience,
) -> RepoProjectionRecord {
    match record {
        RepoProjectionRecord::Graph {
            store_identity,
            store_id,
            roots,
            private_root,
            ..
        } => RepoProjectionRecord::Graph {
            store_identity: store_identity.clone(),
            store_id: *store_id,
            roots: roots.clone(),
            private_root: private_root.clone(),
            marks,
            audience,
        },
        other => other.clone(),
    }
}

/// Whether `record` is a masked copy's graph record of exactly `base`'s
/// store and roots, under any marks.
pub(super) fn same_base(record: &RepoProjectionRecord, base: &RepoProjectionRecord) -> bool {
    matches!(
        record,
        RepoProjectionRecord::Graph {
            audience: RepoProjectionAudience::Masked,
            ..
        }
    ) && graph_record_with(record, Vec::new(), RepoProjectionAudience::Masked) == *base
}

/// The readable marks, in any store, naming a blob the closure `copy`
/// holds (FIX 9105): what its graph record is made under.
pub(super) fn closure_marks(
    facts: &RepoMarkFacts,
    copy: &RepoProjectionCopy,
) -> Result<Vec<EntityId>> {
    let blobs: HashSet<&GitOid> = copy
        .objects
        .iter()
        .filter(|object| object.kind == GitObjectKind::Blob)
        .map(|object| &object.original)
        .collect();
    facts.ids_where(|mark| blobs.contains(&mark.blob_oid))
}

/// Whether the readable marks `facts` name exactly the marks the copy
/// `graph` was made under for its closure (FIX 9105): a mark added, settled
/// or erased on a blob it does not hold keeps it. The closure is read from
/// the masked copy's own object records, one keyed read per marked blob;
/// a recipient copy's is its masked sibling's, which must still stand.
///
/// # Errors
/// A store failure, or a record or mark that does not decode.
pub(crate) fn closure_marks_stand_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    graph: &RepoProjectionClaim,
    facts: &RepoMarkFacts,
) -> Result<bool> {
    let RepoProjectionRecord::Graph {
        marks, audience, ..
    } = &graph.record
    else {
        return Ok(false);
    };
    let closure = match audience {
        RepoProjectionAudience::Masked => graph.graph,
        RepoProjectionAudience::Recipient { .. } => {
            let sibling = masked_sibling(graph)?;
            if RepoProjectionClaim::load_graph_in_txn(vault, txn, &sibling.graph)?.as_ref()
                != Some(&sibling)
            {
                return Ok(false);
            }
            sibling.graph
        }
    };
    let mut held: HashSet<GitOid> = HashSet::new();
    for blob in facts.blob_oids(|_| true) {
        if RepoProjectionClaim::holds_blob_in_txn(vault, txn, &closure, &blob)? {
            held.insert(blob);
        }
    }
    Ok(facts.ids_where(|mark| held.contains(&mark.blob_oid))? == *marks)
}

/// The masked copy's graph record the copy `graph` was made beside: its
/// own for a masked copy, the same store, roots and marks for a
/// recipient's.
///
/// # Errors
/// A failed id derivation.
pub(crate) fn masked_sibling(graph: &RepoProjectionClaim) -> Result<RepoProjectionClaim> {
    let marks = match &graph.record {
        RepoProjectionRecord::Graph { marks, .. } => marks.clone(),
        _ => Vec::new(),
    };
    RepoProjectionClaim::graph(graph_record_with(
        &graph.record,
        marks,
        RepoProjectionAudience::Masked,
    ))
}
