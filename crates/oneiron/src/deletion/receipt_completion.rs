//! The linked REDACTION_AUDIT completion row (OF-470, ARCH-0038 step 10).
//!
//! The sweep never changes a stored receipt. When the historical carriers of
//! receipt R are scrubbed, it appends a second type-72 row C: R's body with
//! `sweep_complete_at` set, freshly signed (OD-6) over C's own id and point
//! envelope. C's id is derived from R's, so R → C needs no index, and a
//! retried sweep finds C instead of writing it twice. Every other field is
//! R's: a row at C's id that differs from R elsewhere is not R's sweep row.
//! C is factual, the sweep alone: the erase's overall completion is its
//! final row's (`receipt_final`, FIX 5844).

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
use super::receipt_grammar::validate_redaction_receipt_body;
use super::receipt_origin::receipt_attested_by_this_device_in_txn;

/// Domain separator of the completion row id derived from its receipt's id.
const REDACTION_SWEEP_COMPLETION_DOMAIN: &[u8] = b"oneiron:redaction-sweep-completion:v1\0";

/// The id of receipt `receipt_id`'s completion row: the first 16 bytes of a
/// domain-separated BLAKE3 of the receipt's id.
pub(crate) fn redaction_sweep_completion_id(receipt_id: &EntityId) -> Result<EntityId> {
    let mut seed = REDACTION_SWEEP_COMPLETION_DOMAIN.to_vec();
    seed.extend_from_slice(receipt_id.as_bytes());
    let digest = blake3::hash(&seed);
    let mut id = [0; 16];
    id.copy_from_slice(&digest.as_bytes()[..16]);
    EntityId::from_bytes(id)
}

/// The row `raw` holds when it is one linked to the initial receipt
/// `receipt`: a valid REDACTION_AUDIT body equal to `receipt` in every field
/// but the two completion times and its own signature.
pub(super) fn linked_row_in(
    raw: &[u8],
    receipt: &RedactionAuditReceipt,
) -> Option<RedactionAuditReceipt> {
    raw.get(ENTITY_METADATA_HEADER_LEN..)
        .filter(|_| raw.first() == Some(&ENTITY_TYPE_REDACTION_AUDIT))
        .filter(|body| validate_redaction_receipt_body(body).is_ok())
        .and_then(|body| decode_redaction_audit_receipt(body).ok())
        .filter(|row| {
            let unlinked = RedactionAuditReceipt {
                sweep_complete_at: receipt.sweep_complete_at,
                erase_complete_at: receipt.erase_complete_at,
                verification: receipt.verification.clone(),
                ..row.clone()
            };
            unlinked == *receipt
        })
}

/// The completion time on `receipt`'s linked completion row, or `None` while
/// its sweep has not completed. The row at the derived id must be a valid
/// REDACTION_AUDIT body linked to the receipt ([`linked_row_in`]) with a
/// `sweep_complete_at` and no `erase_complete_at`. Anything else there is a
/// different occupant: an error the sweep keeps its obligation on, never
/// one it overwrites.
pub(crate) fn redaction_sweep_completion_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    receipt_id: &EntityId,
    receipt: &RedactionAuditReceipt,
) -> Result<Option<u64>> {
    let completion_id = redaction_sweep_completion_id(receipt_id)?;
    let Some(raw) = store.port_entity_raw(txn, &completion_id)? else {
        return Ok(None);
    };
    let completed_at = linked_row_in(&raw, receipt)
        .filter(|completion| completion.erase_complete_at.is_none())
        .and_then(|completion| completion.sweep_complete_at);
    if completed_at.is_none() {
        tracing::error!(
            receipt = %receipt_id.to_hex(),
            "REDACTION_AUDIT: the row at a receipt's completion id is not its linked \
             completion row (fail closed, never overwritten)"
        );
        return Err(Error::CorruptedIndex("redaction audit receipt body"));
    }
    Ok(completed_at)
}

/// Appends `receipt`'s linked completion row, completed at `now`: the sweep's
/// fact alone. The erase's overall "erase completed" is logged with its final
/// row, once its custody retirements have finished too (FIX 5844).
/// Idempotent: when a valid completion row already exists this writes
/// nothing and returns `false`, as it does for a receipt another device
/// attested, which is that device's to complete (FIX 2596). The device key
/// must already be on the handle (P6c): the signer never opens the keystore.
pub(crate) fn append_redaction_sweep_completion_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipt_id: &EntityId,
    receipt: &RedactionAuditReceipt,
    now: u64,
) -> Result<bool> {
    if !receipt.is_initial() {
        return Err(Error::InvariantViolation(
            "a sweep completion row is not completed again",
        ));
    }
    if redaction_sweep_completion_in_txn(&vault.store, wtxn, receipt_id, receipt)?.is_some()
        || !receipt_attested_by_this_device_in_txn(vault, wtxn, receipt_id, receipt)?
    {
        return Ok(false);
    }
    let completion_id = redaction_sweep_completion_id(receipt_id)?;
    let completion = RedactionAuditReceipt {
        sweep_complete_at: Some(now),
        ..receipt.clone()
    };
    let identity = crate::identity::ensure_device_identity_in_txn(vault, wtxn)?;
    let body = sign_redaction_audit_receipt(completion, &completion_id, now, &identity)?;
    validate_redaction_receipt_body(&body)?;
    crate::off_record::FloorWrites::new(&vault.store).append_redaction_audit(
        wtxn,
        &completion_id,
        now,
        &body,
    )?;
    Ok(true)
}
