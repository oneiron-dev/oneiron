//! The housekeeping schedule: one LIVE row per engine sweep.
//!
//! A run writes its start marker before it begins and its finish row after
//! it ends, each in its own transaction. A row that still carries a start
//! marker at the next pass belongs to a run that was interrupted (a crash or
//! a kill): it counts as a failure, so a sweep that takes its process down
//! backs off instead of running first at every restart, and it is never
//! dropped.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::HousekeepingSweep;
use crate::Vault;
use crate::deletion::HARD_ERASE_SWEEP_PREFIX;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// The schedule rows. Key: the sweep's code.
const SCHEDULE: SideTable<String, SweepState, Named> =
    SideTable::new(&side_table::HOUSEKEEPING_SCHEDULE);

/// The first retry after a failure. It doubles with each failure in a row, up
/// to the sweep's cadence and never past an hour.
const RETRY_AFTER_SECS: u64 = 60;
const RETRY_CAP_SECS: u64 = 60 * 60;

/// While an erasure obligation waits, the erasure sweep runs at least this
/// often, whatever its idle cadence.
const HARD_ERASE_BUSY_EVERY: u64 = 60 * 60;

/// One sweep's schedule, in vault-clock seconds.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SweepState {
    /// When the sweep is next due.
    next_due_at: u64,
    /// When its last run ended; 0 before the first.
    finished_at: u64,
    /// When a run in flight started.
    started_at: Option<u64>,
    /// Runs in a row that failed, panicked or were interrupted.
    failures: u32,
    /// When the owner asked for a run that has not started yet. The sweep is
    /// due from then, whatever its cadence says.
    #[serde(default)]
    requested_at: Option<u64>,
    /// Where an unfinished paged walk goes on from; opaque to the schedule.
    #[serde(default)]
    pub(super) cursor: Option<Vec<u8>>,
}

impl SweepState {
    /// The row of a run that ended. A run that finished its walk is due a
    /// cadence later; one that stopped at its bound is due again now and keeps
    /// its cursor. Items the run could not finish count as a failure, so they
    /// are retried after the backoff rather than a whole cadence later.
    pub(super) fn ran(
        self,
        end: u64,
        every: u64,
        cursor: Option<Vec<u8>>,
        complete: bool,
        items_failed: bool,
    ) -> Self {
        let failures = if items_failed {
            self.failures.saturating_add(1)
        } else {
            0
        };
        let next_due_at = if !complete {
            end
        } else if items_failed {
            end.saturating_add(retry_after(failures, every))
        } else {
            end.saturating_add(every)
        };
        Self {
            next_due_at,
            finished_at: end,
            started_at: None,
            failures,
            requested_at: None,
            cursor,
        }
    }

    /// The row of a run in flight. A start marker already there was left by
    /// an interrupted run, which counts as a failure. The owner's request is
    /// answered by this run.
    pub(super) fn started(self, start: u64) -> Self {
        let failures = if self.started_at.is_some() {
            self.failures.saturating_add(1)
        } else {
            self.failures
        };
        Self {
            started_at: Some(start),
            failures,
            requested_at: None,
            ..self
        }
    }

    /// The row of a run that failed or panicked. The cursor stays, so the
    /// retry goes on from the last page that committed.
    pub(super) fn failed(self, end: u64, every: u64) -> Self {
        let failures = self.failures.saturating_add(1);
        Self {
            next_due_at: end.saturating_add(retry_after(failures, every)),
            finished_at: end,
            started_at: None,
            failures,
            requested_at: None,
            ..self
        }
    }

    /// The row of a sweep the owner asked to run that the budget left out:
    /// due from `at` until a run starts.
    pub(super) fn requested(self, at: u64) -> Self {
        Self {
            requested_at: Some(self.requested_at.map_or(at, |earlier| earlier.min(at))),
            ..self
        }
    }
}

fn retry_after(failures: u32, every: u64) -> u64 {
    let doublings = failures.saturating_sub(1).min(16);
    RETRY_AFTER_SECS
        .saturating_mul(1 << doublings)
        .min(every)
        .min(RETRY_CAP_SECS)
}

/// Every engine sweep's row. A row that does not decode reads as absent: the
/// sweep is due, and its next finish row replaces it.
pub(super) fn read_states(vault: &Vault) -> Result<BTreeMap<HousekeepingSweep, SweepState>> {
    let txn = vault.store.env.read_txn()?;
    let mut states = BTreeMap::new();
    for sweep in HousekeepingSweep::ALL {
        if let Some(state) = SCHEDULE.get_lenient(&vault.store, &txn, &sweep.code().to_owned())? {
            states.insert(sweep, state);
        }
    }
    Ok(states)
}

/// When `sweep` is next due: now for one that never ran, after the backoff for
/// one whose run was interrupted, else its stored due time; never later than
/// a run the owner asked for.
pub(super) fn due_at(
    vault: &Vault,
    sweep: HousekeepingSweep,
    state: Option<&SweepState>,
    every: u64,
) -> Result<u64> {
    let Some(state) = state else {
        return Ok(0);
    };
    let scheduled = scheduled_due_at(vault, sweep, state, every)?;
    Ok(state
        .requested_at
        .map_or(scheduled, |requested| requested.min(scheduled)))
}

fn scheduled_due_at(
    vault: &Vault,
    sweep: HousekeepingSweep,
    state: &SweepState,
    every: u64,
) -> Result<u64> {
    if let Some(started) = state.started_at {
        return Ok(started.saturating_add(retry_after(state.failures.saturating_add(1), every)));
    }
    let busy_due = state.finished_at.saturating_add(HARD_ERASE_BUSY_EVERY);
    if sweep == HousekeepingSweep::HardEraseSweep
        && busy_due < state.next_due_at
        && erase_obligation_waiting(vault)?
    {
        return Ok(busy_due);
    }
    Ok(state.next_due_at)
}

pub(super) fn write_state(
    vault: &Vault,
    sweep: HousekeepingSweep,
    state: &SweepState,
) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    SCHEDULE.put(&vault.store, &mut txn, &sweep.code().to_owned(), state)?;
    txn.commit()?;
    Ok(())
}

/// Whether any erasure obligation (an `h:` row) is queued.
pub(super) fn erase_obligation_waiting(vault: &Vault) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let mut rows = vault
        .store
        .sync_queue
        .prefix_iter(&txn, HARD_ERASE_SWEEP_PREFIX)?;
    Ok(rows.next().transpose()?.is_some())
}
