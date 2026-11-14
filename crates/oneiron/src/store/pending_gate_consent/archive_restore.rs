//! Owner restore of archived pending gate-consent tray rows (SIDE-4b G4).
//!
//! Each archived `PENDING_GATE_CONSENT` row lands only when its claim is a
//! live open CLAIM on this vault. A stored byte-identical row reads back
//! `Unchanged` and a different stored row stays live (`KeptLive`); only an
//! absent key lands, through the tray's real put, so indexes, sequence,
//! obligation and seal effects all rebuild fresh. An expired row still
//! installs: the deadline is judged live, never at restore.

use super::PendingGateConsentRecord;
use super::records::vet_pending_gate_consent_record;
use super::tray::TRAY;
use crate::batch::export::archive_side_install::{ArchivedSideRowOutcome, decode_archived_row};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::claim::{ClaimLifecycleStatus, decode_claim_body};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Lands archived tray rows whose claims are live open CLAIMs, rebuilding companions.
pub(crate) fn land_archived_pending_gate_consent_rows_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    _permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
) -> Result<Vec<ArchivedSideRowOutcome>> {
    let mut outcomes = Vec::with_capacity(rows.len());
    for row in rows {
        let outcome = match decode_archived_row(&TRAY, row) {
            Err(reason) => ArchivedSideRowOutcome::HeldBack(reason),
            Ok((key, record)) => land_one_in_txn(vault, txn, &key, &record, row)?,
        };
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

/// Lands one decoded tray row: byte check, claim liveness, then the real put.
fn land_one_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 16],
    record: &PendingGateConsentRecord,
    row: &ArchiveRetainedSideRow,
) -> Result<ArchivedSideRowOutcome> {
    use ArchivedSideRowOutcome::{HeldBack, Installed, KeptLive, Unchanged};
    use RetainedSideHeldBackReason::{InvalidValue, MissingLiveEntity, WrongEntityKind};
    match TRAY.get_bytes(vault, &*txn, key)? {
        Some(stored) if stored == row.source_value => return Ok(Unchanged),
        Some(_) => return Ok(KeptLive),
        None => {}
    }
    // The tray keys a row by the claim it parks; a row naming another claim is not this key's row.
    if record.claim_id != *key {
        return Ok(HeldBack(InvalidValue));
    }
    let Ok(claim_id) = EntityId::from_bytes(*key) else {
        return Ok(HeldBack(InvalidValue));
    };
    match live_entity_row_in_txn(&vault.store, &*txn, &claim_id)? {
        LiveEntityRow::Live { entity_type, body } if entity_type == ENTITY_TYPE_CLAIM => {
            let open = decode_claim_body(&body, true)
                .is_ok_and(|claim| claim.lifecycle == ClaimLifecycleStatus::Active);
            if !open {
                return Ok(HeldBack(MissingLiveEntity));
            }
        }
        LiveEntityRow::Live { .. } => return Ok(HeldBack(WrongEntityKind)),
        LiveEntityRow::Absent | LiveEntityRow::DeletedShell => {
            return Ok(HeldBack(MissingLiveEntity));
        }
    }
    // The put's own vet runs again inside it, but its failure must read back
    // InvalidValue before any write: a CorruptedIndex after TRAY.put would
    // leave a partial install behind a HeldBack report, so the put itself
    // aborts the import on any error.
    if vet_pending_gate_consent_record(record).is_err() {
        return Ok(HeldBack(InvalidValue));
    }
    vault.store.put_pending_gate_consent_in_txn(txn, record)?;
    Ok(Installed)
}
