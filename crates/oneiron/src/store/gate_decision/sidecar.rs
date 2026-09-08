//! Pending-deletion recovery sidecar Store methods and codec.

use heed::{RoTxn, RwTxn};

use crate::error::{Error, Result};
use crate::store::Store;

use super::keys::{deletion_gate_required_key, pending_deletion_gate_decision_key};
use super::types::{
    GateDecisionId, GateDecisionRecord, PENDING_DELETION_GATE_DECISION_VERSION,
    PendingDeletionGateDecisionRecord,
};
use super::vet::vet_gate_decision_record;

impl Store {
    /// Stages the required marker and deletion authority sidecar before a
    /// locally gated tombstone can be committed. The sidecar exists only so a
    /// crash before TXN3 can recover the exact evaluated actor/policy data; it
    /// is never queryable as a Gate decision and is consumed by TXN3.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn put_pending_deletion_gate_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        record: &GateDecisionRecord,
        target: &[u8; 16],
        tombstone_reason: u8,
    ) -> Result<()> {
        let pending = PendingDeletionGateDecisionRecord {
            version: PENDING_DELETION_GATE_DECISION_VERSION,
            target: *target,
            tombstone_reason,
            decision: record.clone(),
        };
        vet_pending_deletion_gate_decision_record(&pending)?;
        let key = pending_deletion_gate_decision_key(record.decision_id);
        let sidecar_exists = if let Some(existing) = self.vault_meta.get(&*wtxn, &key)? {
            let existing = decode_pending_deletion_gate_decision(&existing)?;
            if existing != pending {
                return Err(Error::InvariantViolation(
                    "pending deletion gate decision id collision",
                ));
            }
            true
        } else {
            false
        };
        if !sidecar_exists {
            let value = encode_pending_deletion_gate_decision(&pending)?;
            self.vault_meta.put(wtxn, &key, &value)?;
        }
        let required_key = deletion_gate_required_key(record.decision_id);
        let required_value = encode_deletion_gate_required(target, tombstone_reason);
        if let Some(existing) = self.vault_meta.get(&*wtxn, &required_key)? {
            if *existing != required_value {
                return Err(Error::InvariantViolation(
                    "deletion gate required marker id collision",
                ));
            }
        } else {
            self.vault_meta.put(wtxn, &required_key, &required_value)?;
        }
        Ok(())
    }

    /// Reads a staged deletion authority record by deletion request id.
    #[cfg_attr(not(all(feature = "sync", test)), allow(dead_code))]
    pub(crate) fn pending_deletion_gate_decision_in_txn(
        &self,
        txn: &RoTxn<'_>,
        request_id: GateDecisionId,
    ) -> Result<Option<GateDecisionRecord>> {
        let key = pending_deletion_gate_decision_key(request_id);
        let Some(value) = self.vault_meta.get(txn, &key)? else {
            return Ok(None);
        };
        let pending = decode_pending_deletion_gate_decision(&value)?;
        if pending.decision.decision_id != request_id {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        }
        Ok(Some(pending.decision))
    }

    /// Appends a staged deletion authority record to the real Gate
    /// ledger and removes its recovery sidecar atomically with TXN3.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn append_pending_deletion_gate_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        request_id: GateDecisionId,
        target: &[u8; 16],
        tombstone_reason: u8,
    ) -> Result<Option<GateDecisionRecord>> {
        let required_key = deletion_gate_required_key(request_id);
        let Some(required) = self.vault_meta.get(&*wtxn, &required_key)? else {
            return Ok(None);
        };
        let (required_target, required_reason) = decode_deletion_gate_required(&required)?;
        if required_target != *target || required_reason != tombstone_reason {
            return Ok(None);
        }
        let key = pending_deletion_gate_decision_key(request_id);
        let Some(value) = self.vault_meta.get(&*wtxn, &key)? else {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        };
        let pending = decode_pending_deletion_gate_decision(&value)?;
        if pending.decision.decision_id != request_id {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        }
        if pending.target != *target || pending.tombstone_reason != tombstone_reason {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        }
        self.append_gate_decision_in_txn(wtxn, &pending.decision)?;
        self.vault_meta.delete(wtxn, &key)?;
        self.vault_meta.delete(wtxn, &required_key)?;
        Ok(Some(pending.decision))
    }

    /// Discards a staged recovery sidecar when a later ownership probe proves
    /// this request did not perform a purge. No final Gate record is emitted:
    /// gate evidence must not outlive an unperformed deletion mutation.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn discard_pending_deletion_gate_decision_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        request_id: GateDecisionId,
        target: &[u8; 16],
        tombstone_reason: u8,
    ) -> Result<bool> {
        let required_key = deletion_gate_required_key(request_id);
        let Some(required) = self.vault_meta.get(&*wtxn, &required_key)? else {
            return Ok(false);
        };
        let (required_target, required_reason) = decode_deletion_gate_required(&required)?;
        if required_target != *target || required_reason != tombstone_reason {
            return Ok(false);
        }
        let key = pending_deletion_gate_decision_key(request_id);
        let Some(value) = self.vault_meta.get(&*wtxn, &key)? else {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        };
        let pending = decode_pending_deletion_gate_decision(&value)?;
        if pending.decision.decision_id != request_id {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        }
        if pending.target != *target || pending.tombstone_reason != tombstone_reason {
            return Err(Error::CorruptedIndex("pending deletion gate decision"));
        }
        self.vault_meta.delete(wtxn, &key)?;
        self.vault_meta.delete(wtxn, &required_key)?;
        Ok(true)
    }

    #[cfg(all(test, feature = "sync"))]
    pub(crate) fn remove_pending_deletion_gate_sidecar_for_test(
        &self,
        wtxn: &mut RwTxn<'_>,
        request_id: GateDecisionId,
    ) -> Result<()> {
        self.vault_meta
            .delete(wtxn, &pending_deletion_gate_decision_key(request_id))?;
        Ok(())
    }
}

#[cfg_attr(not(feature = "sync"), allow(dead_code))]
fn encode_pending_deletion_gate_decision(
    record: &PendingDeletionGateDecisionRecord,
) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("pending deletion gate decision encode failed"))
}

#[cfg_attr(not(feature = "sync"), allow(dead_code))]
fn decode_pending_deletion_gate_decision(raw: &[u8]) -> Result<PendingDeletionGateDecisionRecord> {
    let record: PendingDeletionGateDecisionRecord = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("pending deletion gate decision"))?;
    vet_pending_deletion_gate_decision_record(&record)?;
    Ok(record)
}

fn encode_deletion_gate_required(target: &[u8; 16], tombstone_reason: u8) -> [u8; 18] {
    let mut value = [0_u8; 18];
    value[0] = PENDING_DELETION_GATE_DECISION_VERSION;
    value[1] = tombstone_reason;
    value[2..].copy_from_slice(target);
    value
}

fn decode_deletion_gate_required(raw: &[u8]) -> Result<([u8; 16], u8)> {
    let raw: [u8; 18] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("deletion gate required marker"))?;
    if raw[0] != PENDING_DELETION_GATE_DECISION_VERSION || !matches!(raw[1], 1..=4) {
        return Err(Error::CorruptedIndex("deletion gate required marker"));
    }
    let mut target = [0_u8; 16];
    target.copy_from_slice(&raw[2..]);
    Ok((target, raw[1]))
}

#[cfg_attr(not(feature = "sync"), allow(dead_code))]
fn vet_pending_deletion_gate_decision_record(
    record: &PendingDeletionGateDecisionRecord,
) -> Result<()> {
    if record.version != PENDING_DELETION_GATE_DECISION_VERSION
        || !matches!(record.tombstone_reason, 1..=4)
        || record.decision.content_kind != "deletion"
    {
        return Err(Error::CorruptedIndex("pending deletion gate decision"));
    }
    vet_gate_decision_record(&record.decision)
}
