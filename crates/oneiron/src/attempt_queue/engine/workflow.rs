//! Transactional point-claim and retry lineage reads for ordered host composition.

use super::AttemptQueue;
use crate::attempt_queue::encoding::{decode_record, encode_record, ready_at};
use crate::attempt_queue::telemetry::invalid_transition;
use crate::attempt_queue::validate::{lease_claimed_record, validate_lease_owner};
use crate::attempt_queue::{AttemptId, AttemptRecord, ClaimAttempt};
use crate::error::Result;

impl AttemptQueue<'_> {
    /// Claims one known ready row under the ordinary lease-generation fence.
    pub(crate) fn claim_id_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        input: ClaimAttempt,
    ) -> Result<AttemptRecord> {
        validate_lease_owner(&input.lease_owner)?;
        let mut row = self
            .get_in_write_txn(txn, id)?
            .ok_or_else(|| invalid_transition("claim_id", "missing"))?;
        if !row.state.is_ready_indexed() || ready_at(&row) > input.now {
            return Err(invalid_transition("claim_id", row.state.as_str()));
        }
        self.delete_ready_entry_for_record(txn, &row)?;
        lease_claimed_record(&mut row, &input.lease_owner, input.now)?;
        self.store
            .attempt_records
            .put(txn, id.as_bytes(), &encode_record(&row)?)?;
        Ok(row)
    }

    /// Finds a unique retry tip in the transaction that releases the next step.
    pub(crate) fn retry_tip_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        start: AttemptId,
    ) -> Result<AttemptRecord> {
        let mut current = self
            .get_in_write_txn(txn, start)?
            .ok_or_else(|| invalid_transition("retry_tip", "missing"))?;
        let mut seen = std::collections::HashSet::new();
        let mut children = std::collections::HashMap::new();
        for entry in self.store.attempt_records.iter(txn)? {
            let (key, bytes) = entry?;
            let row = decode_record(&bytes, AttemptId::from_bytes(&key)?)?;
            if let Some(parent) = row.retry_of {
                children.entry(parent).or_insert_with(Vec::new).push(row);
            }
        }
        loop {
            if !seen.insert(current.id) || seen.len() > 1024 {
                return Err(invalid_transition("retry_tip", "cycle_or_bound"));
            }
            let Some(mut candidates) = children.remove(&current.id) else {
                return Ok(current);
            };
            if candidates.len() != 1 {
                return Err(invalid_transition("retry_tip", "forked_retry"));
            }
            let next = candidates.remove(0);
            if current.kind != next.kind
                || current.payload != next.payload
                || current.run_id != next.run_id
                || current.task_ref != next.task_ref
                || current.dedupe_key != next.dedupe_key
                || current.dedupe_actor_ref != next.dedupe_actor_ref
                || current.state != crate::attempt_queue::AttemptState::Failed
            {
                return Err(invalid_transition("retry_tip", "lineage_mismatch"));
            }
            current = next;
        }
    }
}
