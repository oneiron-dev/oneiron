//! Doors for `tests/note_review_claim_dependency_backfill.rs` (N1b): strip a
//! CLAIM's NOTE dependencies to the pre-N1 state, reset and read the one-time
//! backfill marker, and plant the bare-ref fixtures the NOTE review cannot
//! produce.

use crate::dreamer_consolidation::{ConsolidationEvidenceEnvelope, encode_consolidation_evidence};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::{TimeRange, Vault};

/// The backfill marker this door resets and reads.
const MARKER: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::NOTE_CLAIM_DEPENDENCY_BACKFILL);

/// Strips `claim`'s dependency rows, both directions, so it reads as a CLAIM
/// the NOTE review learnt before N1.
pub fn forget_note_claim_dependencies(vault: &Vault, claim: EntityId) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        crate::ports::remove_dependency_rows_for_dependent_in_txn(&vault.store, txn, &claim)
    })
}

/// Records that `note` was written from `source`, so deleting `source`
/// withdraws `note` (its stale mark) through the dependent walk.
pub fn record_note_source_dependency(
    vault: &Vault,
    note: EntityId,
    source: EntityId,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        crate::ports::record_derived_edge_in_txn(&vault.store, txn, &note, &source)
    })
}

/// Whether `id` carries the dependent walk's stale mark.
pub fn stale_marked(vault: &Vault, id: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    crate::ports::stale_in_txn(&vault.store, &txn, &id)
}

/// Deletes the backfill marker so the next open runs the pass again.
pub fn reset_note_claim_dependency_backfill(vault: &Vault) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        MARKER.delete(&vault.store, txn, &())?;
        Ok(())
    })
}

/// The Complete counters (scanned, linked, withdrawn, undecodable,
/// missing_without_marker, deleted_ref_type_unknown, archived, stale_note),
/// or None while the pass is not complete.
pub fn note_claim_dependency_backfill_counts(vault: &Vault) -> Result<Option<[u64; 8]>> {
    let txn = vault.store.env.read_txn()?;
    let Some(raw) = MARKER.get_bytes(&vault.store, &txn, &())? else {
        return Ok(None);
    };
    if raw.len() != 65 || raw[0] != 2 {
        return Ok(None);
    }
    let mut counts = [0u64; 8];
    for (slot, chunk) in counts.iter_mut().zip(raw[1..].chunks_exact(8)) {
        *slot = u64::from_be_bytes(
            chunk
                .try_into()
                .map_err(|_| crate::error::Error::CorruptedIndex("backfill marker"))?,
        );
    }
    Ok(Some(counts))
}

/// Writes a CLAIM about `subject` whose consolidation evidence cites `refs`,
/// which the NOTE review cannot produce (a ref it never stored). Its id.
pub fn write_claim_citing_refs(
    vault: &Vault,
    subject: EntityId,
    refs: &[EntityId],
) -> Result<EntityId> {
    use crate::claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    };

    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "preference.coffee",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("an oat milk flat white"),
        0.9,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )?;
    body.evidence = Some(encode_consolidation_evidence(
        &ConsolidationEvidenceEnvelope {
            refs: refs.to_vec(),
            chain: Vec::new(),
            source_meet: ClaimSource::Generated,
        },
    ));
    let at = vault.now_recorded_at();
    vault.put_claim(&id, &body, TimeRange { start: at, end: at }, at)?;
    Ok(id)
}

/// Plants a bare hard-delete (`dt:`) marker for `id`: no captured deletion
/// scope, no NOTE-review row. A removed ref with no NOTE witness.
pub fn plant_bare_hard_delete_marker(vault: &Vault, id: EntityId) -> Result<()> {
    use crate::deletion::{TombstoneReason, TombstoneValueV2};

    let at = vault.now_recorded_at();
    let value = TombstoneValueV2 {
        reason: TombstoneReason::UserHardDelete,
        deleted_at: at,
        request_id: *EntityId::now().as_bytes(),
    };
    vault.with_write_txn_grouped(|txn| {
        crate::deletion::stage_engine_row_hard_erasure_in_txn(&vault.store, txn, &id, at, &value)?;
        Ok(())
    })
}
