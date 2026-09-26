//! Claim-scoped critical-confirm invalidation closures.

use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

use super::GateDecisionId;
use super::Store;
use super::records::{
    CRITICAL_CONFIRM_INVALIDATION_VERSION, CriticalConfirmInvalidationRecord,
    decode_critical_confirm_invalidation, encode_critical_confirm_invalidation,
};

/// Codec fixed `Raw` (see the decls.rs note): [`RawValue`] delegates to
/// [`encode_critical_confirm_invalidation`]/[`decode_critical_confirm_invalidation`].
const INVALIDATION: SideTable<EntityId, CriticalConfirmInvalidationRecord, Raw> =
    SideTable::new(&side_table::CRITICAL_CONFIRM_INVALIDATION);

impl RawValue for CriticalConfirmInvalidationRecord {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_critical_confirm_invalidation(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_critical_confirm_invalidation(bytes)?)
    }
}

impl Store {
    pub(crate) fn critical_confirm_invalidation_exists_in_txn(
        &self,
        txn: &RwTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<bool> {
        let Some(record) = INVALIDATION.get(self, txn, claim_id)? else {
            return Ok(false);
        };
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
        INVALIDATION.delete(self, wtxn, claim_id)?;
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
        INVALIDATION.put(self, wtxn, claim_id, &record)?;
        Ok(())
    }
}
