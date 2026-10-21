//! Owner-bound historical erasure timing from the immutable redaction receipt,
//! its factual sweep row and its overall final row (FIX 5844).

use serde::{Deserialize, Serialize};

use super::support::verify_deletion_authority_in_txn;
use super::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::EntityId;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::consent::AuthenticatedOwner;
use crate::deletion::{
    decode_redaction_audit_receipt, redaction_erase_final_id, redaction_erase_final_in_txn,
    redaction_sweep_completion_id, redaction_sweep_completion_in_txn,
    validate_redaction_receipt_body,
};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;

/// The `redaction:<hex>` receipt ref returned by an erase.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordEraseSweepRequest {
    pub receipt_ref: String,
}

/// Recorded times only: the deadline survives removal of the completed job.
/// No erased body, queued scope, retry error text or inferred deadline is released.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecordEraseSweep {
    pub receipt_ref: String,
    pub request_id: String,
    pub requested_at: u64,
    pub sweep_queued_at: Option<u64>,
    pub deadline_at: Option<u64>,
    pub sweep_complete_at: Option<u64>,
    /// When the erase completed overall, from its signed final row: its
    /// sweep, if it queued one, and every custody retirement it bound had
    /// finished. `None` while either is pending (FIX 5844).
    pub erase_complete_at: Option<u64>,
    /// That final row's `redaction:<hex>` ref, once it is appended.
    pub final_ref: Option<String>,
    /// Where the erased records' key retirements stand on every required
    /// custody target and the anchor; absent when none was in custody here.
    pub custody: Option<RecordEraseCustody>,
}

/// The custody part of an erase (KS-4A2, KS-2A): `custody_retirement_pending`,
/// with each step still owed in order (`custody_retirement_pending`,
/// `body_shared_owner_retained`, `custody_target_pending(<target id>)`,
/// `custody_anchor_pending`), or `custody_retirement_complete`, for the
/// erased records' claim keys and body instance keys alike. The committed
/// erase stands either way.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecordEraseCustody {
    pub state: String,
    pub pending: Vec<String>,
    /// What no erase reaches: bytes read before it.
    pub recall: String,
    /// "rollback not proven: no custody anchor configured" while no anchor
    /// is configured: completion then rests on every required target's
    /// acknowledgement alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// What an erase receipt says no erase reaches (KS-2A).
pub const ERASE_RECALL_NOTE: &str = "bytes already read before the erase cannot be recalled";

impl Memory<'_> {
    /// Reads the receipt, its linked sweep row and its final row in one
    /// owner-checked snapshot.
    pub fn record_erase_sweep_as(
        &self,
        owner: &AuthenticatedOwner,
        input: RecordEraseSweepRequest,
    ) -> MemoryResult<Option<RecordEraseSweep>> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let actor = owner.revalidate_in_txn(self.vault, &txn)?;
        if actor != self.actor {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "the erase sweep is read under the caller's own owner proof",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        verify_deletion_authority_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
        let receipt_id = input
            .receipt_ref
            .strip_prefix("redaction:")
            .and_then(|id| EntityId::from_hex(id).ok())
            .ok_or_else(|| MemoryError::bad_request("expected a redaction:<hex> receipt ref"))?;
        let Some(raw) = self.vault.store.port_entity_raw(&txn, &receipt_id)? else {
            return Ok(None);
        };
        if raw.first() != Some(&ENTITY_TYPE_REDACTION_AUDIT) {
            return Ok(None);
        }
        self.produced_from([receipt_id]);
        let body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(crate::Error::CorruptedIndex("redaction audit receipt body"))?;
        validate_redaction_receipt_body(body)?;
        let receipt = decode_redaction_audit_receipt(body)?;
        // A ref to an appended row reads that row's own times.
        let (sweep_complete_at, erase_complete_at, final_ref) = if receipt.is_initial() {
            let store = &self.vault.store;
            let completed = redaction_sweep_completion_in_txn(store, &txn, &receipt_id, &receipt)?;
            if completed.is_some() {
                self.produced_from([redaction_sweep_completion_id(&receipt_id)?]);
            }
            let erased = redaction_erase_final_in_txn(store, &txn, &receipt_id, &receipt)?;
            let final_id = redaction_erase_final_id(&receipt_id)?;
            if erased.is_some() {
                self.produced_from([final_id]);
            }
            let final_ref = erased.map(|_| format!("redaction:{}", final_id.to_hex()));
            (completed, erased, final_ref)
        } else {
            let final_ref = receipt
                .erase_complete_at
                .map(|_| format!("redaction:{}", receipt_id.to_hex()));
            (
                receipt.sweep_complete_at,
                receipt.erase_complete_at,
                final_ref,
            )
        };
        let claims: Vec<[u8; 16]> = receipt
            .scope
            .entity_ids
            .iter()
            .filter_map(|id| EntityId::from_hex(id).ok())
            .map(|id| *id.as_bytes())
            .collect();
        let custody =
            self.vault
                .erase_custody_in_txn(&txn, &claims)?
                .map(|(state, pending, note)| RecordEraseCustody {
                    state: state.to_owned(),
                    pending,
                    recall: ERASE_RECALL_NOTE.to_owned(),
                    note: note.map(str::to_owned),
                });
        Ok(Some(RecordEraseSweep {
            receipt_ref: format!("redaction:{}", receipt_id.to_hex()),
            request_id: receipt.request_id,
            requested_at: receipt.requested_at,
            sweep_queued_at: receipt.sweep_queued_at,
            deadline_at: receipt.sweep_deadline_at,
            sweep_complete_at,
            erase_complete_at,
            final_ref,
            custody,
        }))
    }
}
