use std::collections::BTreeSet;

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::batch::deindex_lexical_query_hints_for_target;
use crate::edge::EdgeConfirmationStatus;
use crate::edge::EdgeProvenanceFlags;
use crate::entity_id::EntityId;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::ports::{EntityStoreMaintenance, RetrievalIndexMaintenance, ShortIdStoreMaintenance};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::GateDecisionId;
use crate::store::ppr_cache_invalidation as ppr;
use crate::store::vad_annotation::delete_vad_annotation_metadata_for_type_in_txn;
use crate::store::vad_annotation::delete_vad_annotation_metadata_in_txn;
use crate::store::vad_annotation::vad_annotation_delete_scope_exists_in_txn;
use crate::write_envelope::claim_body::ClaimSubject;
use crate::write_envelope::provenance::EdgeRef;
use crate::write_envelope::provenance::PREDICATE_EDGE_PROVENANCE;
use crate::write_envelope::provenance::codec::decode_edge_provenance_body;
use crate::write_envelope::provenance::edge_lifecycle::ProvenancePrecedence;
use crate::write_envelope::provenance::edge_lifecycle::StoredProvenanceClaim;
use crate::write_envelope::provenance::edge_lifecycle::winner_index;
use crate::write_envelope::vad_annotation::VadAnnotationCleanup;

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

/// What a delete's pre-scrub capture found (ARCH-0038).
pub(super) enum ProvenanceCapture {
    /// No bodied CLAIM, or a CLAIM that is no `edge.provenance` one.
    NotApplicable,
    /// A healthy `edge.provenance` Claim's subject and sweep refs.
    Captured(CapturedProvenanceDelete),
    /// A hard erase of a classified corrupt CLAIM: the audited exception
    /// (FIX 7800).
    CaptureFailed(corrupt::CorruptCapture),
}

impl ProvenanceCapture {
    /// The healthy provenance capture, when there is one.
    pub(super) fn refs(&self) -> Option<&CapturedProvenanceDelete> {
        match self {
            Self::Captured(captured) => Some(captured),
            _ => None,
        }
    }

    /// The audited corrupt-CLAIM exception, when this capture took it.
    pub(super) fn corrupt(&self) -> Option<&corrupt::CorruptCapture> {
        match self {
            Self::CaptureFailed(corrupt) => Some(corrupt),
            _ => None,
        }
    }
}

/// Builds the queued sweep row's delete-interplay extras from a pre-purge
/// capture: opaque lowercase-hex identifiers only — never content or
/// predicate strings. A healthy provenance capture gives its refs, the
/// audited corrupt-CLAIM exception its capture failure (FIX 7800). Empty for
/// every other delete, so its queued row shape gains nothing.
pub(super) fn sweep_extras(capture: &ProvenanceCapture) -> HardEraseSweepExtras {
    let captured = match capture {
        ProvenanceCapture::NotApplicable => return HardEraseSweepExtras::default(),
        ProvenanceCapture::Captured(captured) => captured,
        ProvenanceCapture::CaptureFailed(corrupt) => {
            return HardEraseSweepExtras {
                capture_failures: vec![corrupt.failure()],
                ..HardEraseSweepExtras::default()
            };
        }
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
        capture_failures: Vec::new(),
    }
}

/// The refs a hard delete captured before its SoftErase emptied the Claim body, by erased id, until
/// a purge queues its sweep (F25 H10): a purge refused or cut off after that commit captures
/// nothing on retry. Each record is a kind byte and the 16-byte ref. A held relayed ask intent's
/// record outlives the sweep, until a due legal-hold pass retires it (FIX 20468).
const PENDING_SWEEP_REFS: crate::side_table::SideTable<HexId, Vec<u8>, crate::side_table::Raw> =
    crate::side_table::SideTable::new(&crate::side_table::DELETION_PENDING_SWEEP_REFS);
const SWEEP_REF_REVISION: u8 = 1;
const SWEEP_REF_BODY_SNAPSHOT: u8 = 2;
/// A row an erase of the id retired with it: its id joins the scope of the receipt and sweep the
/// erase's writer queues (FIX 7494).
const SWEEP_REF_RETIRED_ROW: u8 = 3;
/// A relayed ask intent of the id that a legal hold on it or on its result kept from the id's
/// erase: the due legal-hold pass that finds neither held retires both (FIX 20468). It stays
/// when the receipt takes the other records, and the erase is not complete while it does.
const SWEEP_REF_HELD_ASK_FORWARD_INTENT: u8 = 4;
const SWEEP_REF_RECORD_LEN: usize = 17;

/// Stages `rows`, the rows an erase of `id` retired with it in this transaction, for the receipt
/// and sweep its writer queues: each id joins their scope (FIX 7494).
pub(super) fn stage_retired_rows_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    rows: &BTreeSet<EntityId>,
) -> Result<()> {
    stage_records_in_txn(vault, wtxn, id, SWEEP_REF_RETIRED_ROW, rows)
}

/// Records, in the erase's writer, that `intents`, relayed ask intents of `holder` that a legal
/// hold kept from its erase, are owed their retirement and their results' (FIX 20468). The writer
/// that puts a held intent or result after that erase records it the same way (FIX 7494).
pub(crate) fn owe_held_ask_forward_intents_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    holder: &EntityId,
    intents: &BTreeSet<EntityId>,
) -> Result<()> {
    stage_records_in_txn(
        vault,
        wtxn,
        holder,
        SWEEP_REF_HELD_ASK_FORWARD_INTENT,
        intents,
    )
}

/// Every relayed ask intent a legal hold kept from an erase, each with the erased holder whose
/// row records it (FIX 20468).
pub(crate) fn held_ask_forward_intents_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(EntityId, EntityId)>> {
    let mut owed = Vec::new();
    for row in PENDING_SWEEP_REFS.iter_from(&vault.store, txn, &[])? {
        let (HexId(holder), value) = row?;
        // A row that does not decode is its receipt's to refuse.
        if value.len() % SWEEP_REF_RECORD_LEN != 0 {
            continue;
        }
        for record in value.chunks_exact(SWEEP_REF_RECORD_LEN) {
            if let [SWEEP_REF_HELD_ASK_FORWARD_INTENT, intent @ ..] = record {
                let intent: [u8; 16] = intent
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("pending sweep refs"))?;
                owed.push((holder, EntityId::from_bytes(intent)?));
            }
        }
    }
    Ok(owed)
}

/// Whether the erase of one of `ids` still owes a relayed ask intent a legal hold kept, and its
/// result, their retirement (FIX 20468). The erase is not complete while it does.
pub(super) fn held_ask_forward_intents_owed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ids: &[EntityId],
) -> Result<bool> {
    for id in ids {
        let Some(value) = PENDING_SWEEP_REFS.get(&vault.store, txn, &HexId(*id))? else {
            continue;
        };
        if value
            .chunks_exact(SWEEP_REF_RECORD_LEN)
            .any(|record| record.first() == Some(&SWEEP_REF_HELD_ASK_FORWARD_INTENT))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Clears `holder`'s record that `intent` is owed its retirement (FIX 20468). The row goes with
/// its last record.
pub(crate) fn clear_held_ask_forward_intent_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    holder: &EntityId,
    intent: &EntityId,
) -> Result<()> {
    let key = HexId(*holder);
    let Some(value) = PENDING_SWEEP_REFS.get(&vault.store, wtxn, &key)? else {
        return Ok(());
    };
    let mut owed = vec![SWEEP_REF_HELD_ASK_FORWARD_INTENT];
    owed.extend_from_slice(intent.as_bytes());
    let kept: Vec<u8> = value
        .chunks_exact(SWEEP_REF_RECORD_LEN)
        .filter(|record| *record != owed.as_slice())
        .flatten()
        .copied()
        .collect();
    if kept.is_empty() {
        PENDING_SWEEP_REFS.delete(&vault.store, wtxn, &key)?;
        return Ok(());
    }
    PENDING_SWEEP_REFS.put(&vault.store, wtxn, &key, &kept)
}

/// Appends one `kind` record per id of `rows` to the row staged for `id`, each once.
fn stage_records_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    kind: u8,
    rows: &BTreeSet<EntityId>,
) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let key = HexId(*id);
    let mut value = PENDING_SWEEP_REFS
        .get(&vault.store, wtxn, &key)?
        .unwrap_or_default();
    for row in rows {
        let mut record = vec![kind];
        record.extend_from_slice(row.as_bytes());
        if !value
            .chunks(SWEEP_REF_RECORD_LEN)
            .any(|staged| staged == record.as_slice())
        {
            value.extend(record);
        }
    }
    PENDING_SWEEP_REFS.put(&vault.store, wtxn, &key, &value)
}

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
/// Returns the rows its erase retired with it, whose ids join the receipt's scope (FIX 7494).
/// A held relayed intent's record stays for the due legal-hold pass (FIX 20468).
pub(super) fn take_staged_sweep_refs_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    extras: &mut HardEraseSweepExtras,
) -> Result<Vec<EntityId>> {
    let key = HexId(*id);
    let Some(value) = PENDING_SWEEP_REFS.get(&vault.store, wtxn, &key)? else {
        return Ok(Vec::new());
    };
    if value.len() % SWEEP_REF_RECORD_LEN != 0 {
        return Err(Error::CorruptedIndex("pending sweep refs"));
    }
    let mut retired = Vec::new();
    let mut kept = Vec::new();
    for record in value.chunks_exact(SWEEP_REF_RECORD_LEN) {
        let (kind, reference) = record.split_at(1);
        let slot = match kind {
            [SWEEP_REF_REVISION] => &mut extras.revision_ids,
            [SWEEP_REF_BODY_SNAPSHOT] => &mut extras.body_snapshot_refs,
            [SWEEP_REF_RETIRED_ROW] => {
                let row: [u8; 16] = reference
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("pending sweep refs"))?;
                retired.push(EntityId::from_bytes(row)?);
                continue;
            }
            [SWEEP_REF_HELD_ASK_FORWARD_INTENT] => {
                kept.extend_from_slice(record);
                continue;
            }
            _ => return Err(Error::CorruptedIndex("pending sweep refs")),
        };
        let hex = bytes_to_hex_lower(reference);
        if !slot.contains(&hex) {
            slot.push(hex);
        }
    }
    if kept.is_empty() {
        PENDING_SWEEP_REFS.delete(&vault.store, wtxn, &key)?;
    } else {
        PENDING_SWEEP_REFS.put(&vault.store, wtxn, &key, &kept)?;
    }
    Ok(retired)
}

mod active_store;
mod corrupt;
mod markers;
mod provenance;
mod redirect_shells;
mod replay;
mod scope_probes;

pub use corrupt::CorruptClaimRepair;
pub(crate) use corrupt::classified_corrupt_claim_in_txn;
pub(super) use corrupt::take_corrupt_capture_in_txn;
pub(crate) use scope_probes::TombstoneScopeProbes;
