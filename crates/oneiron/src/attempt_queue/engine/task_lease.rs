//! Named-task lease doors for the task highway (OF-220): claim the one ready
//! try of a named TASK, and renew a held lease on an explicit report.
//!
//! The actorless [`AttemptQueue::claim`] stays plumbing no agent touches:
//! these doors take the TASK and the try the highway already resolved, and a
//! lease owner the highway derived from the authenticated actor.

use crate::attempt_queue::encoding::{decode_record, ready_at, ready_key};
use crate::attempt_queue::telemetry::invalid_transition;
use crate::attempt_queue::types::{
    AttemptId, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
};
use crate::attempt_queue::validate::{
    lease_claimed_record, validate_kind, validate_lease_owner, validate_transition_lease,
};
use crate::error::Result;

use super::AttemptQueue;

impl AttemptQueue<'_> {
    /// Leases the try `id` of the TASK `task_ref` in the caller's
    /// transaction, when it is that TASK's ready row of `kind`.
    ///
    /// `Empty` when the row is not ready yet (a retry still backing off, or
    /// a TASK whose symbols are held), and when its TASK waits on an
    /// unattached comment, which the claim pauses for that hold (OF-368). A
    /// row of another TASK or kind, or one past readiness, is refused rather
    /// than leased.
    pub(crate) fn claim_for_task_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        task_ref: &str,
        kind: &str,
        input: ClaimAttempt,
    ) -> Result<ClaimOutcome> {
        validate_kind(kind)?;
        validate_lease_owner(&input.lease_owner)?;
        let Some(raw_record) = self.store.attempt_records.get(wtxn, id.as_bytes())? else {
            return Err(invalid_transition("claim_for_task", "missing"));
        };
        let mut record = decode_record(&raw_record, id)?;
        if record.task_ref.as_deref() != Some(task_ref) || record.kind != kind {
            return Err(invalid_transition("claim_for_task", "other_task"));
        }
        if !record.state.is_ready_indexed() {
            return Err(invalid_transition("claim_for_task", record.state.as_str()));
        }
        let now = input
            .now
            .min(crate::ports::recorded_at_in_txn(self.store, wtxn)?);
        let record_ready_at = ready_at(&record);
        if record_ready_at > now
            || !crate::task_verb::task_dispatch_ready(self.store, &*wtxn, Some(task_ref), now)?
        {
            return Ok(ClaimOutcome::Empty);
        }
        if let Some(hold) = self.annotation_hold_for_row_in_txn(&*wtxn, &record)? {
            self.hold_for_annotation_in_txn(wtxn, id, hold, now)?;
            return Ok(ClaimOutcome::Empty);
        }
        let key = ready_key(record_ready_at, id);
        lease_claimed_record(&mut record, &input.lease_owner, now)?;
        crate::task_verb::acquire_task_symbols(self.store, wtxn, Some(task_ref), now)?;
        self.store.attempt_ready.delete(wtxn, &key)?;
        self.put_record_in_txn(wtxn, &mut record)?;
        Ok(ClaimOutcome::Claimed(record))
    }

    /// Moves a held lease's expiry clock, on an explicit renewal only.
    ///
    /// Fenced like every lease transition, and refused in
    /// [`AttemptState::Landing`]: a landing has one bounded window, so no
    /// report may silently extend it. Progress without the flag never calls
    /// this; a note is never a hidden heartbeat.
    pub(crate) fn renew_lease_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        lease_owner: &str,
        attempt_count: u32,
        now: u64,
    ) -> Result<AttemptRecord> {
        validate_lease_owner(lease_owner)?;
        let Some(raw_record) = self.store.attempt_records.get(wtxn, id.as_bytes())? else {
            return Err(invalid_transition("renew_lease", "missing"));
        };
        let mut record = decode_record(&raw_record, id)?;
        if record.state != AttemptState::Leased {
            return Err(invalid_transition("renew_lease", record.state.as_str()));
        }
        validate_transition_lease(&record, lease_owner, attempt_count, "renew_lease")?;
        record.updated_at = now.max(record.updated_at);
        self.put_record_in_txn(wtxn, &mut record)?;
        Ok(record)
    }

    fn put_record_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        record: &mut AttemptRecord,
    ) -> Result<()> {
        let encoded = self.encode_in_txn(wtxn, record)?;
        self.store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        Ok(())
    }
}
