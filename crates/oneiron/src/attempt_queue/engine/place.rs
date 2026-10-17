//! Placement inside a caller-owned writer: a row enqueued in the same
//! transaction takes its worker and parent there, so a multi-item operation
//! opens its run-tree root and children in one commit.

use std::collections::HashSet;

use super::AttemptQueue;
use crate::attempt_queue::encoding::decode_record;
use crate::attempt_queue::telemetry::invalid_transition;
use crate::attempt_queue::validate::validate_lease_owner;
use crate::attempt_queue::{AttemptId, AttemptPlacement, AttemptRecord, AttemptState};
use crate::error::Result;

impl AttemptQueue<'_> {
    /// Places a queued or paused row in the caller's writer, with
    /// [`Self::redirect`]'s refusal of a self, cyclic or cross-run parent.
    /// No lease is live on such a row, so nothing is fenced, and no operator
    /// event is recorded: the placement is the row's own, made with it.
    pub(crate) fn place_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        placement: AttemptPlacement,
    ) -> Result<AttemptRecord> {
        if let Some(worker) = &placement.worker {
            validate_lease_owner(worker)?;
        }
        let raw = self
            .store
            .attempt_records
            .get(txn, id.as_bytes())?
            .ok_or_else(|| invalid_transition("place", "missing"))?;
        let mut record = decode_record(&raw, id)?;
        if !matches!(record.state, AttemptState::Queued | AttemptState::Paused) {
            return Err(invalid_transition("place", record.state.as_str()));
        }
        if record.placement.as_ref() == Some(&placement) {
            return Ok(record);
        }
        let mut seen = HashSet::from([record.id]);
        let mut parent = placement.parent;
        while let Some(ancestor_id) = parent {
            if !seen.insert(ancestor_id) {
                return Err(invalid_transition("place", "parent cycle"));
            }
            let raw = self
                .store
                .attempt_records
                .get(txn, ancestor_id.as_bytes())?
                .ok_or_else(|| invalid_transition("place", "missing parent"))?;
            let ancestor = decode_record(&raw, ancestor_id)?;
            if record.run_id.is_none() || ancestor.run_id != record.run_id {
                return Err(invalid_transition("place", "different run"));
            }
            parent = crate::run_tree::effective_parent(&ancestor);
        }
        record.placement = Some(placement);
        let encoded = self.encode_in_txn(txn, &mut record)?;
        self.store
            .attempt_records
            .put(txn, record.id.as_bytes(), &encoded)?;
        Ok(record)
    }
}
