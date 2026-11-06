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
//! lease can never settle the next one. The ordinary door keeps every
//! failure separately. The opt-in coalescing door keeps consecutive equal
//! failures as one entry with their first and latest instant and count.

use crate::attempt_queue::encoding::{decode_record, ready_at, ready_key};
use crate::attempt_queue::telemetry::invalid_transition;
use crate::attempt_queue::types::{AttemptId, AttemptRecord, AttemptState};
use crate::attempt_queue::validate::{
    validate_failure_reason, validate_lease_owner, validate_transition_lease,
};
use crate::error::Result;

use super::AttemptQueue;
pub use crate::store::attempt_record::RequeuedFailure;
pub(in crate::attempt_queue) use crate::store::attempt_record_codec::validate_requeued_history;

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
        self.requeue_with_history(input, false)
    }

    /// [`Self::requeue`] with consecutive failures by the same worker for
    /// the same reason counted together. Each entry keeps its first lease
    /// generation and instant, its latest instant, and its failure count.
    /// A gap in lease generations starts a new entry.
    pub fn requeue_coalescing(&self, input: RequeueAttempt) -> Result<AttemptRecord> {
        self.requeue_with_history(input, true)
    }

    fn requeue_with_history(&self, input: RequeueAttempt, coalesce: bool) -> Result<AttemptRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let requeued = self.requeue_with_history_in_txn(&mut wtxn, input, coalesce)?;
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
        self.requeue_with_history_in_txn(wtxn, input, false)
    }

    fn requeue_with_history_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: RequeueAttempt,
        coalesce: bool,
    ) -> Result<AttemptRecord> {
        let now = crate::ports::recorded_at_in_txn(self.store, wtxn)?;
        let Some(raw) = self.store.attempt_records.get(wtxn, input.id.as_bytes())? else {
            return Err(invalid_transition("requeue", "missing"));
        };
        let mut row = decode_record(&raw, input.id)?;
        if row.state != AttemptState::Leased {
            return Err(invalid_transition("requeue", row.state.as_str()));
        }
        validate_lease_owner(&input.lease_owner)?;
        validate_transition_lease(&row, &input.lease_owner, input.attempt_count, "requeue")?;
        validate_failure_reason(&input.reason)?;

        let mut reason = input.reason.clone();
        if coalesce {
            match self.vault {
                Some(vault) => crate::batch::secret_scan::admit_typed(
                    vault,
                    wtxn,
                    ("attempt", input.id.as_bytes()),
                    &mut reason,
                )?,
                None => crate::batch::secret_scan::admit_typed(
                    self.store,
                    wtxn,
                    ("attempt", input.id.as_bytes()),
                    &mut reason,
                )?,
            };
        }

        if coalesce
            && let Some(last) = row.history.last_mut()
            && last.lease_owner == input.lease_owner
            && last.reason == reason
            && u64::from(last.attempt_count) + u64::from(last.count) == u64::from(row.attempt_count)
            && let Some(count) = last.count.checked_add(1)
        {
            last.count = count;
            last.last_at = now;
        } else {
            row.history.push(RequeuedFailure {
                at: now,
                last_at: now,
                count: 1,
                lease_owner: input.lease_owner,
                attempt_count: row.attempt_count,
                reason,
            });
        }
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
