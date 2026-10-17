//! The linked REDACTION_AUDIT completion row (OF-470, ARCH-0038 step 10).
//!
//! The sweep never changes a stored receipt. When the historical carriers of
//! receipt R are scrubbed, it appends a second type-72 row C: R's body with
//! `sweep_complete_at` set, freshly signed (OD-6) over C's own id and point
//! envelope. C's id is derived from R's, so R → C needs no index, and a
//! retried sweep finds C instead of writing it twice. Shared `request_id` and
//! scope are the request link; the derived id is the exact-parent link.

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
use crate::store::Store;

use super::receipt::{
    RedactionAuditReceipt, decode_redaction_audit_receipt, sign_redaction_audit_receipt,
    validate_redaction_receipt_body,
};

/// Domain separator of the completion row id derived from its receipt's id.
const REDACTION_SWEEP_COMPLETION_DOMAIN: &[u8] = b"oneiron:redaction-sweep-completion:v1\0";

/// The id of receipt `receipt_id`'s completion row: the first 16 bytes of a
/// domain-separated BLAKE3 of the receipt's id.
fn redaction_sweep_completion_id(receipt_id: &EntityId) -> Result<EntityId> {
    let mut seed = REDACTION_SWEEP_COMPLETION_DOMAIN.to_vec();
    seed.extend_from_slice(receipt_id.as_bytes());
    let digest = blake3::hash(&seed);
    let mut id = [0; 16];
    id.copy_from_slice(&digest.as_bytes()[..16]);
    EntityId::from_bytes(id)
}

/// The completion time on `receipt`'s linked completion row, or `None` while
/// its sweep has not completed. The row at the derived id must be a valid
/// REDACTION_AUDIT body carrying the receipt's `request_id`, its scope and a
/// `sweep_complete_at`. Anything else there is a different occupant: an
/// error the sweep keeps its obligation on, never one it overwrites.
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
    let completed_at = raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .filter(|_| raw[0] == ENTITY_TYPE_REDACTION_AUDIT)
        .filter(|body| validate_redaction_receipt_body(body).is_ok())
        .and_then(|body| decode_redaction_audit_receipt(body).ok())
        .filter(|completion| {
            completion.request_id == receipt.request_id && completion.scope == receipt.scope
        })
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

/// Appends `receipt`'s linked completion row, completed at `now`, and logs
/// a legal hold's "erase completed" for its request in the same txn (C4: the
/// linked receipt pair is now complete). Idempotent: when a valid completion
/// row already exists this writes nothing and returns `false`. The device key
/// must already be on the handle (P6c): the signer never opens the keystore.
pub(crate) fn append_redaction_sweep_completion_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipt_id: &EntityId,
    receipt: &RedactionAuditReceipt,
    now: u64,
) -> Result<bool> {
    if receipt.sweep_complete_at.is_some() {
        return Err(Error::InvariantViolation(
            "a sweep completion row is not completed again",
        ));
    }
    if redaction_sweep_completion_in_txn(&vault.store, wtxn, receipt_id, receipt)?.is_some() {
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
    crate::store::legal_hold::note_erase_completed_in_txn(
        &vault.store,
        wtxn,
        &receipt.scope.entity_ids,
        &receipt.request_id,
        now,
    )?;
    Ok(true)
}
