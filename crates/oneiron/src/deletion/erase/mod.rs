use std::collections::BTreeSet;

use crate::Vault;
use crate::affect::VadAnnotationCleanup;
use crate::affect::delete_vad_annotation_metadata_for_type_in_txn;
use crate::affect::delete_vad_annotation_metadata_in_txn;
use crate::affect::vad_annotation_delete_scope_exists_in_txn;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::batch::deindex_lexical_query_hints_for_target;
use crate::claim::ClaimSubject;
use crate::edge::EdgeConfirmationStatus;
use crate::edge::EdgeProvenanceFlags;
use crate::entity_id::EntityId;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::ports::{EntityStoreMaintenance, RetrievalIndexMaintenance, ShortIdStoreMaintenance};
use crate::ppr;
use crate::provenance::EdgeRef;
use crate::provenance::PREDICATE_EDGE_PROVENANCE;
use crate::provenance::ProvenancePrecedence;
use crate::provenance::StoredProvenanceClaim;
use crate::provenance::decode_edge_provenance_body;
use crate::provenance::downgrade_edge_to_bare;
use crate::provenance::restamp_edge_flags;
use crate::provenance::winner_index;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::GateDecisionId;

use super::receipt::{RedactionReceiptInput, RedactionScope};
use super::sweep_queue::HardEraseSweepExtras;
use super::tombstone;
use super::tombstone::DecodedTombstoneValue;
use super::tombstone::{
    HARD_DELETE_MARKER, IDENTITY_SOFT_DELETE_MARKER, ROW_DELETION_FENCE,
    ROW_DELETION_FENCE_BACKFILLED, ReplayedTombstoneOutcome, decode_tombstone_value,
};
use super::topology_delete_intent::{
    clear_own_topology_delete_in_txn, guard_topology_delete_request_in_txn,
    settled_topology_delete_in_txn,
};
use crate::error::{ClaimError, RegistryError};
use crate::side_table::HexId;

/// ARCH-0038 delete-interplay refs captured from an `edge.provenance` Claim
/// BEFORE its body is purged or SoftErased: the subject EdgeRef whose cached
/// flags must be refreshed post-purge (D16), and the opaque refs the queued
/// historical-carrier sweep rides on (the ONE-1091 executor's seam).
pub(super) struct CapturedProvenanceDelete {
    pub(super) subject: EdgeRef,
    source_revision_ref: Option<[u8; 16]>,
    body_snapshot_ref: Option<[u8; 16]>,
}

/// Builds the queued sweep row's delete-interplay extras from a pre-purge
/// provenance capture: opaque lowercase-hex identifiers only — never content
/// or predicate strings. Empty for non-provenance deletes, so their queued
/// row shape gains nothing.
pub(super) fn sweep_extras(captured: Option<&CapturedProvenanceDelete>) -> HardEraseSweepExtras {
    let Some(captured) = captured else {
        return HardEraseSweepExtras::default();
    };
    HardEraseSweepExtras {
        revision_ids: captured
            .source_revision_ref
            .iter()
            .map(|reference| bytes_to_hex_lower(reference))
            .collect(),
        body_snapshot_refs: captured
            .body_snapshot_ref
            .iter()
            .map(|reference| bytes_to_hex_lower(reference))
            .collect(),
    }
}

/// The refs a hard delete captured before its SoftErase emptied the Claim body, by erased id, until
/// a purge queues its sweep (F25 H10): a purge refused or cut off after that commit captures
/// nothing on retry. Each record is a kind byte and the 16-byte ref.
const PENDING_SWEEP_REFS: crate::side_table::SideTable<HexId, Vec<u8>, crate::side_table::Raw> =
    crate::side_table::SideTable::new(&crate::side_table::DELETION_PENDING_SWEEP_REFS);
const SWEEP_REF_REVISION: u8 = 1;
const SWEEP_REF_BODY_SNAPSHOT: u8 = 2;
const SWEEP_REF_RECORD_LEN: usize = 17;

/// Stages `captured`'s sweep refs in the SoftErase transaction that empties their Claim body.
pub(super) fn stage_sweep_refs_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    captured: &CapturedProvenanceDelete,
) -> Result<()> {
    let key = HexId(*id);
    let mut value = PENDING_SWEEP_REFS
        .get(&vault.store, wtxn, &key)?
        .unwrap_or_default();
    for (kind, reference) in [
        (SWEEP_REF_REVISION, captured.source_revision_ref),
        (SWEEP_REF_BODY_SNAPSHOT, captured.body_snapshot_ref),
    ] {
        let Some(reference) = reference else {
            continue;
        };
        let mut record = vec![kind];
        record.extend_from_slice(&reference);
        if !value
            .chunks(SWEEP_REF_RECORD_LEN)
            .any(|staged| staged == record.as_slice())
        {
            value.extend(record);
        }
    }
    if value.is_empty() {
        return Ok(());
    }
    PENDING_SWEEP_REFS.put(&vault.store, wtxn, &key, &value)
}

/// Adds the refs staged for `id` to the sweep being queued, and drops them in the same commit.
pub(super) fn take_staged_sweep_refs_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    extras: &mut HardEraseSweepExtras,
) -> Result<()> {
    let key = HexId(*id);
    let Some(value) = PENDING_SWEEP_REFS.get(&vault.store, wtxn, &key)? else {
        return Ok(());
    };
    if value.len() % SWEEP_REF_RECORD_LEN != 0 {
        return Err(Error::CorruptedIndex("pending sweep refs"));
    }
    for record in value.chunks_exact(SWEEP_REF_RECORD_LEN) {
        let (kind, reference) = record.split_at(1);
        let slot = match kind {
            [SWEEP_REF_REVISION] => &mut extras.revision_ids,
            [SWEEP_REF_BODY_SNAPSHOT] => &mut extras.body_snapshot_refs,
            _ => return Err(Error::CorruptedIndex("pending sweep refs")),
        };
        let hex = bytes_to_hex_lower(reference);
        if !slot.contains(&hex) {
            slot.push(hex);
        }
    }
    PENDING_SWEEP_REFS.delete(&vault.store, wtxn, &key)?;
    Ok(())
}

mod active_store;
mod markers;
mod provenance;
mod redirect_shells;
mod replay;
