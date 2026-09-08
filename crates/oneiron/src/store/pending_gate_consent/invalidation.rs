//! Claim-scoped critical-confirm invalidation closures.

use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::GateDecisionId;
use super::Store;
use super::keys::critical_confirm_invalidation_key;
use super::records::{
    CRITICAL_CONFIRM_INVALIDATION_VERSION, CriticalConfirmInvalidationRecord,
    decode_critical_confirm_invalidation, encode_critical_confirm_invalidation,
};

impl Store {
    pub(crate) fn critical_confirm_invalidation_exists_in_txn(
        &self,
        txn: &RwTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<bool> {
        let Some(raw) = self
            .vault_meta
            .get(txn, &critical_confirm_invalidation_key(claim_id.as_bytes()))?
        else {
            return Ok(false);
        };
        let record = decode_critical_confirm_invalidation(&raw)?;
        if record.claim_id != *claim_id.as_bytes() {
            return Err(Error::CorruptedIndex("critical confirm invalidation"));
        }
        // The record also retains the first replacement hash for audit, but a
        // closure is claim-scoped: a different later peer body is not a fresh
        // local ceremony and must not re-promote Auto either.
        let _ = record.replacement_body_hash;
        let _ = record.invalidated_decision_id;
        Ok(true)
    }

    /// Clears the claim-scoped invalidation only when a new local critical
    /// ceremony has successfully attached its own pending binding. Ordinary
    /// pending rows, replicated replays, and entity deletion never clear it.
    pub(crate) fn delete_critical_confirm_invalidation_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<()> {
        self.vault_meta.delete(
            wtxn,
            &critical_confirm_invalidation_key(claim_id.as_bytes()),
        )?;
        Ok(())
    }

    pub(crate) fn put_critical_confirm_invalidation_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        claim_id: &EntityId,
        invalidated_decision_id: GateDecisionId,
        replacement_body: &[u8],
    ) -> Result<()> {
        let record = CriticalConfirmInvalidationRecord {
            version: CRITICAL_CONFIRM_INVALIDATION_VERSION,
            claim_id: *claim_id.as_bytes(),
            invalidated_decision_id,
            replacement_body_hash: *blake3::hash(replacement_body).as_bytes(),
        };
        self.vault_meta.put(
            wtxn,
            &critical_confirm_invalidation_key(claim_id.as_bytes()),
            &encode_critical_confirm_invalidation(&record)?,
        )?;
        Ok(())
    }
}
