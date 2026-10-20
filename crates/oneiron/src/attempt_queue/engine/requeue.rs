//! Same-intent requeue (FIX 5240): a leased try its worker answered failed goes
//! back to the queue as the SAME row, so one intent stays one row however
//! often it is tried.
//!
//! [`AttemptQueue::retry`] finalizes the source and mints a fresh row per try;
//! that stays the door for work whose every try is its own receipt. A
//! requeue instead keeps the row's id, payload, dedupe key, run, lineage,
//! manifest and lease-generation fence, appends the failure to the row's
//! [`AttemptRecord::history`], and schedules the row at the caller's due
//! instant. Its next claim advances the fence, so an answer to the failed
//! lease can never settle the next one. Nothing is capped, dropped or
//! coalesced: every failure stays on the row, repeats included.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::encoding::{decode_record, ready_at, ready_key};
use crate::attempt_queue::telemetry::invalid_transition;
use crate::attempt_queue::types::{AttemptId, AttemptRecord, AttemptState};
use crate::attempt_queue::validate::{
    validate_failure_reason, validate_lease_owner, validate_transition_lease,
};
use crate::error::Result;

use super::AttemptQueue;

/// One failed try a requeue kept on its row: when it was recorded, the lease
/// it ended and the worker's reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequeuedFailure {
    /// The vault's recorded instant the failure was kept at.
    pub at: u64,
    /// The owner of the lease the failure ended.
    pub lease_owner: String,
    /// That lease's generation within the row.
    pub attempt_count: u32,
    /// The worker's reason, as it gave it.
    pub reason: String,
}

/// Input of [`AttemptQueue::requeue`]: the lease it answers, the failure and
/// the instant the row becomes claimable again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequeueAttempt {
    pub id: AttemptId,
    pub lease_owner: String,
    /// The lease generation the failure answers; any other refuses.
    pub attempt_count: u32,
    /// The worker's nonempty reason.
    pub reason: String,
    /// When the row is claimable again.
    pub due_at: u64,
}

impl AttemptQueue<'_> {
    /// Requeues a leased try its worker failed, as the same row: the failure
    /// joins the row's history, the lease ends and the row waits in
    /// [`AttemptState::Scheduled`] until `due_at`. Fenced by owner and exact
    /// lease generation, so a stale or repeated answer changes nothing.
    pub fn requeue(&self, input: RequeueAttempt) -> Result<AttemptRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let requeued = self.requeue_in_txn(&mut wtxn, input)?;
        wtxn.commit()?;
        self.store.notify_attempt_observers();
        Ok(requeued)
    }

    /// [`Self::requeue`] inside a caller-owned transaction; the caller must
    /// abort it on error.
    pub(crate) fn requeue_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: RequeueAttempt,
    ) -> Result<AttemptRecord> {
        let now = crate::ports::recorded_at_in_txn(self.store, wtxn)?;
        let Some(raw) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("requeue", "missing"));
        };
        let mut row = decode_record(raw, input.id)?;
        if row.state != AttemptState::Leased {
            return Err(invalid_transition("requeue", row.state.as_str()));
        }
        validate_lease_owner(&input.lease_owner)?;
        validate_transition_lease(&row, &input.lease_owner, input.attempt_count, "requeue")?;
        validate_failure_reason(&input.reason)?;

        row.history.push(RequeuedFailure {
            at: now,
            lease_owner: input.lease_owner,
            attempt_count: row.attempt_count,
            reason: input.reason.clone(),
        });
        row.last_error = Some(input.reason);
        row.state = AttemptState::Scheduled;
        row.lease_owner = None;
        row.scheduled_at = Some(input.due_at);
        row.backoff_until = None;
        row.updated_at = now;

        let encoded = self.encode_in_txn(wtxn, &mut row)?;
        self.store
            .attempt_records
            .put(wtxn, row.id.as_bytes(), &encoded)?;
        // A leased row holds no ready entry; the requeued one enters the
        // index at its own due instant. Its run and dedupe entries already
        // name this row, so neither moves.
        self.store.attempt_ready.put(
            wtxn,
            &ready_key(ready_at(&row), row.id),
            row.id.as_bytes(),
        )?;
        Ok(row)
    }
}

/// Refuses a stored history entry no requeue could have written.
pub(in crate::attempt_queue) fn validate_requeued_history(
    history: &[RequeuedFailure],
) -> Result<()> {
    for failure in history {
        validate_lease_owner(&failure.lease_owner)?;
        validate_failure_reason(&failure.reason)?;
    }
    Ok(())
}
