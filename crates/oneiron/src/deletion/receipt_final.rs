//! An erase's overall final REDACTION_AUDIT row (FIX 5844, C-ERASE-FINAL).
//!
//! An erase's initial receipt R never changes. Its historical sweep appends
//! the factual sweep row C (`receipt_completion`). Once the sweep, when R
//! queued one, and every custody retirement R binds by name have finished,
//! one more row F is appended: R's body with C's sweep time and
//! `erase_complete_at`, freshly signed (OD-6) over F's own id, which is
//! derived from R's under its own domain. The legal hold's "erase completed"
//! is logged with F, once. Whichever finishes last appends F: an erase that
//! queued no sweep and owes no custody retirement gets it in its own
//! transaction, the sweep in its finalize transaction, a custody
//! publication pass once its locks are released, and the custody tick of a
//! running server retries it, settled or not. A missing proof keeps F owed;
//! nothing waits on F: not the erase, its response nor a backup.

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
use crate::store::Store;

use super::receipt::{
    RedactionAuditReceipt, decode_redaction_audit_receipt, sign_redaction_audit_receipt,
};
use super::receipt_completion::{linked_row_in, redaction_sweep_completion_in_txn};
use super::receipt_grammar::validate_redaction_receipt_body;

/// Domain separator of the final row id derived from its receipt's id.
const REDACTION_ERASE_FINAL_DOMAIN: &[u8] = b"oneiron:redaction-erase-final:v1\0";

/// The id of receipt `receipt_id`'s overall final row: the first 16 bytes of
/// a domain-separated BLAKE3 of the receipt's id.
pub(crate) fn redaction_erase_final_id(receipt_id: &EntityId) -> Result<EntityId> {
    let mut seed = REDACTION_ERASE_FINAL_DOMAIN.to_vec();
    seed.extend_from_slice(receipt_id.as_bytes());
    let digest = blake3::hash(&seed);
    let mut id = [0; 16];
    id.copy_from_slice(&digest.as_bytes()[..16]);
    EntityId::from_bytes(id)
}

/// The erase's overall completion time on the initial receipt `receipt`'s
/// final row, or `None` while it has none. The row at the derived id must be
/// linked to the receipt, carry `erase_complete_at`, and carry the linked
/// sweep row's time when the receipt queued a sweep (none otherwise).
/// Anything else there is a different occupant: an error, never overwritten.
pub(crate) fn redaction_erase_final_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    receipt_id: &EntityId,
    receipt: &RedactionAuditReceipt,
) -> Result<Option<u64>> {
    let final_id = redaction_erase_final_id(receipt_id)?;
    let Some(raw) = store.port_entity_raw(txn, &final_id)? else {
        return Ok(None);
    };
    let swept = match receipt.sweep_queued_at {
        Some(_) => redaction_sweep_completion_in_txn(store, txn, receipt_id, receipt)?,
        None => None,
    };
    let completed_at = linked_row_in(&raw, receipt)
        .filter(|row| row.sweep_complete_at == swept)
        .and_then(|row| row.erase_complete_at);
    if completed_at.is_none() {
        tracing::error!(
            receipt = %receipt_id.to_hex(),
            "REDACTION_AUDIT: the row at a receipt's final id is not its linked final row \
             (fail closed, never overwritten)"
        );
        return Err(Error::CorruptedIndex("redaction audit receipt body"));
    }
    Ok(completed_at)
}

/// Where an erase's overall completion stands.
enum EraseFinal {
    /// Its final row is there.
    Appended,
    /// Owed now: its sweep, if it queued one, finished at this time, and
    /// every custody retirement it binds has finished.
    Due(Option<u64>),
    /// Its sweep or a custody retirement it binds has not finished.
    Pending,
}

/// Reads where the erase of the initial receipt `receipt` stands. A custody
/// fault is warned and leaves it pending, as every custody fault an erase
/// meets is.
fn erase_final_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    receipt_id: &EntityId,
    receipt: &RedactionAuditReceipt,
) -> Result<EraseFinal> {
    if redaction_erase_final_in_txn(store, txn, receipt_id, receipt)?.is_some() {
        return Ok(EraseFinal::Appended);
    }
    let swept = match receipt.sweep_queued_at {
        Some(_) => match redaction_sweep_completion_in_txn(store, txn, receipt_id, receipt)? {
            Some(at) => Some(at),
            None => return Ok(EraseFinal::Pending),
        },
        None => None,
    };
    let retired = store
        .erase_custody_retired_in_txn(txn, &receipt.custody_retirements)
        .unwrap_or_else(|error| {
            tracing::warn!(
                receipt = %receipt_id.to_hex(),
                kind = ?error.kind(),
                "an erase's custody retirements did not read; its final row stays owed"
            );
            false
        });
    Ok(if retired {
        EraseFinal::Due(swept)
    } else {
        EraseFinal::Pending
    })
}

/// Appends the initial receipt `receipt`'s overall final row, completed at
/// `now`, once its sweep, if it queued one, and every custody retirement it
/// binds have finished, and logs a legal hold's "erase completed" for its
/// request in the same transaction (C4), the one place that event is
/// written. `false` when it is not owed yet or is there already, or when a
/// different row sits at a linked id (logged there, never overwritten). The
/// device key must already be on the handle (P6c).
pub(crate) fn finish_redaction_erase_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipt_id: &EntityId,
    receipt: &RedactionAuditReceipt,
    now: u64,
) -> Result<bool> {
    if !receipt.is_initial() {
        return Err(Error::InvariantViolation(
            "only an erase's initial receipt gets a final row",
        ));
    }
    let swept = match erase_final_in_txn(&vault.store, wtxn, receipt_id, receipt) {
        Ok(EraseFinal::Due(swept)) => swept,
        Ok(EraseFinal::Appended | EraseFinal::Pending)
        | Err(Error::CorruptedIndex("redaction audit receipt body")) => return Ok(false),
        Err(error) => return Err(error),
    };
    let final_id = redaction_erase_final_id(receipt_id)?;
    let row = RedactionAuditReceipt {
        sweep_complete_at: swept,
        erase_complete_at: Some(now),
        ..receipt.clone()
    };
    let identity = crate::identity::ensure_device_identity_in_txn(vault, wtxn)?;
    let body = sign_redaction_audit_receipt(row, &final_id, now, &identity)?;
    validate_redaction_receipt_body(&body)?;
    crate::off_record::FloorWrites::new(&vault.store).append_redaction_audit(
        wtxn,
        &final_id,
        now,
        &body,
    )?;
    crate::store::legal_hold::note_erase_completed_in_txn(
        &vault.store,
        wtxn,
        &receipt.scope.entity_ids,
        &receipt.request_id,
        now,
    )?;
    Ok(true)
}

/// The initial receipt stored at `id`, when `id` holds one: a sweep or final
/// row, or a body the receipt grammar refuses (the sweep's audit reports
/// those), is none.
fn initial_receipt_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<RedactionAuditReceipt>> {
    let Some(raw) = store.port_entity_raw(txn, id)? else {
        return Ok(None);
    };
    Ok(raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .filter(|_| raw.first() == Some(&ENTITY_TYPE_REDACTION_AUDIT))
        .filter(|body| validate_redaction_receipt_body(body).is_ok())
        .and_then(|body| decode_redaction_audit_receipt(body).ok())
        .filter(RedactionAuditReceipt::is_initial))
}

impl Vault {
    /// Appends the overall final row of every erase whose sweep and custody
    /// retirements have all finished but that has none yet (FIX 5844): the
    /// retry after a crash, a fault, or a custody pass that completed a
    /// retirement. Reads every initial receipt, then writes each owed row in
    /// its own transaction, so one fault leaves the others to land. Returns
    /// the rows appended.
    ///
    /// # Errors
    ///
    /// Storage faults reading the receipts. One receipt's fault is warned and
    /// left for the next pass.
    pub fn finish_redaction_erases(&self) -> Result<u64> {
        let due = {
            let txn = self.store.env.read_txn()?;
            let mut due = Vec::new();
            for id in self
                .store
                .port_entity_ids_by_type(&txn, ENTITY_TYPE_REDACTION_AUDIT, None)?
            {
                let id = id?;
                let state = initial_receipt_in_txn(&self.store, &txn, &id)?
                    .map(|receipt| erase_final_in_txn(&self.store, &txn, &id, &receipt))
                    .transpose();
                match state {
                    Ok(Some(EraseFinal::Due(_))) => due.push(id),
                    // A different row at a linked id is logged where it is
                    // read: that erase stays pending.
                    Ok(_) | Err(Error::CorruptedIndex("redaction audit receipt body")) => {}
                    Err(error) => return Err(error),
                }
            }
            due
        };
        if due.is_empty() {
            return Ok(0);
        }
        // Each row is signed in its transaction: the device key first (P6c).
        // One that cannot load refuses in the signer, warned below.
        let _ = self.prepare_install_signing();
        let mut appended = 0_u64;
        for id in due {
            let finished = self.with_write_txn_grouped(|wtxn| {
                let Some(receipt) = initial_receipt_in_txn(&self.store, wtxn, &id)? else {
                    return Ok(false);
                };
                let now = self.store.clock.now_recorded_at();
                finish_redaction_erase_in_txn(self, wtxn, &id, &receipt, now)
            });
            match finished {
                Ok(true) => appended = appended.saturating_add(1),
                Ok(false) => {}
                Err(error) => tracing::warn!(
                    receipt = %id.to_hex(),
                    kind = ?error.kind(),
                    "an erase's final row was not appended; the next pass retries"
                ),
            }
        }
        Ok(appended)
    }

    /// [`Self::finish_redaction_erases`], its fault warned: the custody pass
    /// or tick it rides never fails for it.
    pub fn finish_redaction_erases_logged(&self) {
        match self.finish_redaction_erases() {
            Ok(0) => {}
            Ok(appended) => tracing::info!(appended, "erase final rows appended"),
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "owed erase final rows were not appended; the next pass retries"
            ),
        }
    }
}
