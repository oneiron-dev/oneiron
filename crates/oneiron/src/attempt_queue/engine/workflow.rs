//! Transactional point-claim and retry lineage reads for ordered host composition.

use super::AttemptQueue;
use crate::attempt_queue::encoding::{decode_record, ready_at};
use crate::attempt_queue::telemetry::invalid_transition;
use crate::attempt_queue::validate::{lease_claimed_record, validate_lease_owner};
use crate::attempt_queue::{
    AttemptId, AttemptRecord, AttemptState, CancelMode, ClaimAttempt, ClaimOutcome,
};
use crate::error::Result;
use crate::limit_ask::EngineLimit;

impl AttemptQueue<'_> {
    /// Claims one known ready row with the ordinary claim's admission: the
    /// row's placed worker, readiness at the smaller of the caller's and the
    /// recorded clock, task dispatch readiness and task symbols. The lease is
    /// stamped with the recorded clock. A row this owner may not take yet is
    /// `Empty`; so is a row whose TASK waits on an unattached comment, which
    /// the claim pauses for that hold (OF-368).
    pub(crate) fn claim_id_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        mut input: ClaimAttempt,
    ) -> Result<ClaimOutcome> {
        validate_lease_owner(&input.lease_owner)?;
        let cutoff = input.now;
        input.now = crate::ports::recorded_at_in_txn(self.store, txn)?;
        let cutoff = cutoff.min(input.now);
        self.claim_id_storage_in_txn(txn, id, input, cutoff)
    }

    /// [`Self::claim_id_in_txn`] stamped at the caller's `input.now`, ready by
    /// `cutoff`: it persists no clock floor, so the claim writes nothing
    /// outside the job tables.
    pub(crate) fn claim_id_storage_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        input: ClaimAttempt,
        cutoff: u64,
    ) -> Result<ClaimOutcome> {
        validate_lease_owner(&input.lease_owner)?;
        let mut row = self
            .get_in_write_txn(txn, id)?
            .ok_or_else(|| invalid_transition("claim_id", "missing"))?;
        if !row.state.is_ready_indexed() {
            return Err(invalid_transition("claim_id", row.state.as_str()));
        }
        if ready_at(&row) > cutoff
            || !row.accepts_worker(&input.lease_owner)
            || !crate::task_verb::task_dispatch_ready(
                self.store,
                &*txn,
                row.task_ref.as_deref(),
                input.now,
            )?
        {
            return Ok(ClaimOutcome::Empty);
        }
        if let Some(hold) = self.annotation_hold_for_row_in_txn(&*txn, &row)? {
            self.hold_for_annotation_in_txn(txn, id, hold, input.now)?;
            return Ok(ClaimOutcome::Empty);
        }
        crate::task_verb::acquire_task_symbols(
            self.store,
            txn,
            row.task_ref.as_deref(),
            input.now,
        )?;
        self.delete_ready_entry_for_record(txn, &row)?;
        lease_claimed_record(&mut row, &input.lease_owner, input.now)?;
        let encoded = self.encode_in_txn(txn, &mut row)?;
        self.store
            .attempt_records
            .put(txn, id.as_bytes(), &encoded)?;
        Ok(ClaimOutcome::Claimed(row))
    }

    /// Finds a unique retry tip in the transaction that releases the next step.
    ///
    /// A row visited twice is a cycle and refuses; a long lineage does not.
    /// Each superseded try must have settled as a lineage continues (FIX
    /// 9577): failed, landed by its worker, or abandoned with its evidence.
    /// The whole lineage is read; past the `[limits]` `attempt_retry_tip_rows`
    /// row the finished walk asks whether everything is okay (Rule 5).
    pub(crate) fn retry_tip_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        start: AttemptId,
    ) -> Result<AttemptRecord> {
        let mut current = self
            .get_in_txn(txn, start)?
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
            if !seen.insert(current.id) {
                return Err(invalid_transition("retry_tip", "cycle"));
            }
            let Some(mut candidates) = children.remove(&current.id) else {
                self.store
                    .limit_watch
                    .measure(EngineLimit::AttemptRetryTipRows, seen.len() as u64);
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
                || !current.continues_retry_lineage()
            {
                return Err(invalid_transition("retry_tip", "lineage_mismatch"));
            }
            current = next;
        }
    }

    /// The newest try of `start`'s retry lineage, for a read: each try's one
    /// retry followed forward, a landing successor included. `None` when a
    /// try has two retries or the walk meets a row twice, so no one try is
    /// newest. Unlike [`Self::retry_tip_in_txn`] it releases nothing and asks
    /// nothing of the rows' fields; a long lineage asks through the
    /// `attempt_retry_tip_rows` row and is still read whole (Rule 5).
    pub(crate) fn newest_retry_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        start: AttemptId,
    ) -> Result<Option<AttemptId>> {
        let mut children = std::collections::HashMap::<AttemptId, Vec<AttemptId>>::new();
        for entry in self.store.attempt_records.iter(txn)? {
            let (key, bytes) = entry?;
            let row = decode_record(&bytes, AttemptId::from_bytes(&key)?)?;
            if let Some(parent) = row.retry_of {
                children.entry(parent).or_default().push(row.id);
            }
        }
        let mut seen = std::collections::HashSet::from([start]);
        let mut current = start;
        while let Some(next) = children.get(&current) {
            let [next] = next.as_slice() else {
                return Ok(None);
            };
            if !seen.insert(*next) {
                return Ok(None);
            }
            current = *next;
        }
        self.store
            .limit_watch
            .measure(EngineLimit::AttemptRetryTipRows, seen.len() as u64);
        Ok(Some(current))
    }
}

impl AttemptRecord {
    /// Whether this settled try may be superseded by its one retry in a
    /// released lineage (FIX 9577): it failed; or it was cancelled by a
    /// designed landing (never a forced stop); or it was abandoned with its
    /// evidence, its result reference and its recorded exhaust. The retry tip
    /// and the workflow context door read the same rule.
    pub(crate) fn continues_retry_lineage(&self) -> bool {
        match self.state {
            AttemptState::Failed => true,
            AttemptState::Cancelled => {
                self.cancel_state
                    .cancellation
                    .as_ref()
                    .is_some_and(|cancellation| {
                        cancellation.mode == CancelMode::Landed && cancellation.grounds.is_none()
                    })
            }
            AttemptState::Abandoned => {
                self.result_ref.is_some()
                    && self.last_error.is_some()
                    && self.terminal_exhaust.is_some()
            }
            AttemptState::Queued
            | AttemptState::Leased
            | AttemptState::Paused
            | AttemptState::Scheduled
            | AttemptState::Landing
            | AttemptState::Completed => false,
        }
    }
}

impl AttemptQueue<'_> {
    /// Brings a waiting retry's instant forward to `now` (FIX 1112): the try a
    /// failure ladder minted becomes ready at once instead of at its backoff.
    /// Only a `Scheduled` retry still waiting on a later instant moves; any
    /// other row is left as it is and reads `false`. Its tries and its ladder
    /// are unchanged: only the wait is cut.
    pub(crate) fn advance_retry_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        now: u64,
    ) -> Result<bool> {
        let Some(mut record) = self.get_in_write_txn(txn, id)? else {
            return Ok(false);
        };
        if record.state != AttemptState::Scheduled
            || record.retry_of.is_none()
            || ready_at(&record) <= now
        {
            return Ok(false);
        }
        self.delete_ready_entry_for_record(txn, &record)?;
        record.scheduled_at = Some(now);
        record.backoff_until = None;
        let encoded = self.encode_in_txn(txn, &mut record)?;
        self.store
            .attempt_records
            .put(txn, record.id.as_bytes(), &encoded)?;
        self.store.attempt_ready.put(
            txn,
            &crate::attempt_queue::encoding::ready_key(now, record.id),
            record.id.as_bytes(),
        )?;
        Ok(true)
    }
}
