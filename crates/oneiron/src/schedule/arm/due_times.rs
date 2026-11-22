//! A row's due and finish times, read and pulled inside a write.

use super::{ROWS, ScheduleRow, row_key, store_row_in_txn};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::schedule::{JobSpec, Trigger, job_named, retry_after};
use crate::store::Store;

/// The engine arms `spec` about `subject` due at `at` at the latest, inside the caller's write:
/// a row not armed, or due later, is armed afresh at a time ([`Trigger::At`]), with no failure,
/// cursor or request; one already due by `at` is left as it is. A row with a run in flight is
/// armed due now, so the run's end leaves it due at its first retry and the next run answers
/// from the work: work a write made due during a run is never lost, and the run's own answer
/// (more work, its next due time, its retries) is never pushed back to `at`. The door of a job
/// whose one row stands for a line of work, due at its earliest item, which a new item may pull
/// earlier.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn arm_at_latest_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    spec: &'static JobSpec,
    subject: Option<EntityId>,
    at: u64,
) -> Result<()> {
    let key = row_key(spec.code, subject);
    let prior = ROWS.get(store, txn, &key)?;
    if prior
        .as_ref()
        .is_some_and(|prior| prior.started_at.is_none() && prior.due_at() <= at)
    {
        return Ok(());
    }
    let now = crate::ports::recorded_at_in_txn(store, txn)?;
    let at = if prior
        .as_ref()
        .is_some_and(|prior| prior.started_at.is_some())
    {
        at.min(now)
    } else {
        at
    };
    let row = ScheduleRow::armed(Trigger::At { at }, None, prior.as_ref(), now)?;
    store_row_in_txn(store, txn, &key, prior.as_ref(), Some(&row))
}

/// Pulls the due time of `job` about `subject` forward to `at` inside the caller's write: work
/// a door made due before the job's next occurrence. A job with a run in flight keeps its due
/// time, and that run's end makes it due by `at` (the run read its work before this write); a
/// job that is backing off keeps its due time; one not armed, or already due by `at`, is left as
/// it is.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn due_by_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    job: &str,
    subject: Option<EntityId>,
    at: u64,
) -> Result<()> {
    let key = row_key(job, subject);
    let Some(prior) = ROWS.get(store, txn, &key)? else {
        return Ok(());
    };
    let row = if prior.started_at.is_some() {
        if prior.pulled_to.is_some_and(|pulled| pulled <= at) {
            return Ok(());
        }
        ScheduleRow {
            pulled_to: Some(at),
            ..prior.clone()
        }
    } else {
        if prior.failures > 0 || prior.due_at() <= at {
            return Ok(());
        }
        ScheduleRow {
            next_due_at: at,
            ..prior.clone()
        }
    };
    store_row_in_txn(store, txn, &key, Some(&prior), Some(&row))
}

/// When the last run of `job` about `subject` ended (0 before the first), or `None` when it is
/// not armed.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn finished_at_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    job: &str,
    subject: Option<EntityId>,
) -> Result<Option<u64>> {
    Ok(ROWS
        .get(store, txn, &row_key(job, subject))?
        .map(|row| row.finished_at))
}

/// A run of `job` about `subject` started at `at` and never finished, as a crash or a kill leaves
/// it: its start marker. Nothing when the job is not armed.
///
/// # Errors
///
/// Storage errors.
#[cfg(oneiron_test_support)]
pub(crate) fn plant_start_marker_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    job: &str,
    subject: Option<EntityId>,
    at: u64,
) -> Result<()> {
    let key = row_key(job, subject);
    let Some(prior) = ROWS.get(store, txn, &key)? else {
        return Ok(());
    };
    let row = ScheduleRow {
        started_at: Some(at),
        ..prior.clone()
    };
    store_row_in_txn(store, txn, &key, Some(&prior), Some(&row))
}

/// When `job` about `subject` is next due, or `None` when it is not armed: a requested run's
/// time or its next due time, and for a run that never finished, the retry after it.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn due_at_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    job: &str,
    subject: Option<EntityId>,
) -> Result<Option<u64>> {
    let Some(row) = ROWS.get(store, txn, &row_key(job, subject))? else {
        return Ok(None);
    };
    Ok(Some(match (row.started_at, job_named(job)) {
        (Some(started), Some(spec)) => started.saturating_add(retry_after(
            row.failures.saturating_add(1),
            spec.retry_first_secs,
            spec.retry_cap(&row.trigger),
        )),
        _ => row.due_at(),
    }))
}
