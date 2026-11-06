//! Checkpoint content for a SKILL head's two independent parted values.
//!
//! Snapshot history uses the entity document's actor codec. FIRST remains
//! its exact immutable Candidate row under the SKILL owner, as the generic
//! entity-row getter places that kind. Neither content holds the snapshot's
//! original part digests: rejoining derives each leg's manifest anew.

use serde::{Deserialize, Serialize};

use super::{CarriedHead, RefinementOriginParts, decode, encode};
use crate::EntityId;
use crate::entity_doc::{RefinementOriginSource, join_entity_doc_loro, split_entity_doc_loro};
use crate::error::Result;
use crate::ports::checkpoint::{EntityRowPlacement, entity_row_placement};
use crate::store::checkpoint_payload::loro::{Atom, OpenedRow};
use crate::store::checkpoint_payload::rows::{RoundTripPolicy, Unresolved, bad_part};
use crate::sync::carrier_parts::{Parts, join_parts_from, split_parts};
use crate::vault::entity_revision::RevisionRef;

/// Only the document history names actors; its framed no-one form and the
/// actor-free record values share the entity's content compartment.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Content {
    record: crate::entity_doc::CarriedRecordDocument,
    row: Vec<u8>,
    snapshot: Vec<u8>,
    refinement: Option<RefinementContent>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefinementContent {
    revision: RevisionRef,
    row: Vec<u8>,
}

/// A captured pair's content and the actors removed by the native history
/// codec. This is checkpoint data, never native operation admission.
pub(crate) struct SplitRecordDocument {
    pub(crate) entity: EntityId,
    pub(crate) content: Vec<u8>,
    pub(crate) actors: Vec<Atom>,
}

/// The actual restored head and each leg's pieces, kept apart even when a
/// digest occurs in both legs or more than once within one leg.
pub(crate) struct RecordDocumentTransport {
    pub(crate) head: Vec<u8>,
    pub(crate) snapshot: Vec<(String, Vec<u8>)>,
    pub(crate) refinement: Vec<(String, Vec<u8>)>,
}

/// Splits one captured historical head with its exact entities-map row and
/// the parts its own capture holds. Missing or unproved content stays with
/// the window's existing unclassified route; no current receiver head is read.
pub(crate) fn split<B: AsRef<[u8]>>(
    key: &str,
    head: &[u8],
    row: &[u8],
    mut part: impl FnMut(&str) -> Option<B>,
) -> std::result::Result<SplitRecordDocument, Unresolved> {
    let (carried, entity) = decode(head).map_err(|_| Unresolved::Undecodable)?;
    if entity.to_hex() != key || !matches!(entity_row_placement(row), EntityRowPlacement::Owner) {
        return Err(Unresolved::Undecodable);
    }
    let snapshot = joined_leg(&carried.snapshot, &mut part)?;
    carried
        .record
        .document(row, &snapshot)
        .map_err(|_| Unresolved::Undecodable)?;
    let refinement = match &carried.refinement {
        Some(source) => {
            let raw = joined_leg(&source.row, &mut part)?;
            if !matches!(entity_row_placement(&raw), EntityRowPlacement::Owner) {
                return Err(Unresolved::Undecodable);
            }
            RefinementOriginSource::from_carried(&carried.record, source.revision, raw.clone())
                .map_err(|_| Unresolved::Undecodable)?;
            Some(RefinementContent {
                revision: source.revision,
                row: raw,
            })
        }
        None => None,
    };
    let mut split = split_entity_doc_loro(&[&snapshot], RoundTripPolicy::HistoryEquivalent)?;
    let split = split.pop().ok_or(Unresolved::Undecodable)?;
    let content = Content {
        record: carried.record,
        row: row.to_vec(),
        snapshot: split.content,
        refinement,
    };
    let content = rmp_serde::to_vec_named(&content).map_err(|_| Unresolved::Undecodable)?;
    // Exercise the real two-leg rejoin before the capture emits anything.
    join(&content, split.atoms.clone()).map_err(|_| Unresolved::Undecodable)?;
    Ok(SplitRecordDocument {
        entity,
        content,
        actors: split.atoms,
    })
}

/// Rebuilds the opened history and independently re-parts snapshot and
/// FIRST. The original logical row, source identity and permanent FIRST
/// hash still bind; changing an actor changes only the rebuilt history and
/// the actual snapshot's part digests, not native permission.
pub(crate) fn join(content: &[u8], actors: Vec<Atom>) -> Result<RecordDocumentTransport> {
    let decoded: Content = rmp_serde::from_slice(content).map_err(|_| bad_part())?;
    if rmp_serde::to_vec_named(&decoded).map_err(|_| bad_part())? != content
        || !matches!(
            entity_row_placement(&decoded.row),
            EntityRowPlacement::Owner
        )
    {
        return Err(bad_part());
    }
    let mut snapshots = join_entity_doc_loro(&[OpenedRow {
        content: &decoded.snapshot,
        atoms: actors,
    }])?;
    let snapshot = snapshots.pop().ok_or_else(bad_part)?;
    decoded.record.document(&decoded.row, &snapshot)?;
    let (snapshot, snapshot_pieces) = parted(&snapshot)?;
    let (refinement, refinement_pieces) = match decoded.refinement {
        Some(source) => {
            if !matches!(entity_row_placement(&source.row), EntityRowPlacement::Owner) {
                return Err(bad_part());
            }
            RefinementOriginSource::from_carried(
                &decoded.record,
                source.revision,
                source.row.clone(),
            )?;
            let (row, pieces) = parted(&source.row)?;
            (
                Some(RefinementOriginParts {
                    revision: source.revision,
                    row,
                }),
                pieces,
            )
        }
        None => (None, Vec::new()),
    };
    let head = encode(&CarriedHead {
        record: decoded.record,
        snapshot,
        refinement,
    })?;
    Ok(RecordDocumentTransport {
        head,
        snapshot: snapshot_pieces,
        refinement: refinement_pieces,
    })
}

/// Checks the original per-leg boundaries too, not only the concatenated
/// length and digests. A short final piece in one leg is never combined
/// with the first piece in the other.
fn joined_leg<B: AsRef<[u8]>>(
    manifest: &Parts,
    part: impl FnMut(&str) -> Option<B>,
) -> std::result::Result<Vec<u8>, Unresolved> {
    let bytes = join_parts_from(manifest, part).ok_or(Unresolved::Undecodable)?;
    let (spelled, _) = split_parts(&bytes).map_err(|_| Unresolved::Undecodable)?;
    if spelled != *manifest {
        return Err(Unresolved::Undecodable);
    }
    Ok(bytes)
}

fn parted(bytes: &[u8]) -> Result<(Parts, Vec<(String, Vec<u8>)>)> {
    let (parts, pieces) = split_parts(bytes)?;
    Ok((
        parts,
        pieces
            .into_iter()
            .map(|(key, bytes)| (key, bytes.to_vec()))
            .collect(),
    ))
}
