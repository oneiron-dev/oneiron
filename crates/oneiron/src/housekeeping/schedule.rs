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
use crate::deletion::{HARD_ERASE_SWEEP_PREFIX, WITHDRAWN_GENERATION_SWEEP_PREFIX};
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
    /// An earlier run of the walk in progress left items it could not finish.
    #[serde(default)]
    cycle_failed: bool,
    /// The run in flight, or the one that goes on from an unfinished,
    /// failed or interrupted run, answers an owner's request.
    #[serde(default)]
    owners: bool,
}

impl SweepState {
    /// The row of a run that ended. A run that stopped at its bound is due
    /// again now and keeps its cursor and any failure its walk met so far. A
    /// walk that finished is due a cadence later, unless some run of it left
    /// items it could not finish: that counts as a failure, so the next walk,
    /// which retries them, comes after the backoff.
    pub(super) fn ran(
        self,
        end: u64,
        every: u64,
        cursor: Option<Vec<u8>>,
        complete: bool,
        items_failed: bool,
    ) -> Self {
        let cycle_failed = self.cycle_failed || items_failed;
        let answered = complete && !cycle_failed;
        let (next_due_at, failures, cycle_failed) = if !complete {
            (end, self.failures, cycle_failed)
        } else if cycle_failed {
            let failures = self.failures.saturating_add(1);
            (
                end.saturating_add(retry_after(failures, every)),
                failures,
                false,
            )
        } else {
            (end.saturating_add(every), 0, false)
        };
        Self {
            next_due_at,
            finished_at: end,
            started_at: None,
            failures,
            requested_at: None,
            cursor,
            cycle_failed,
            owners: self.owners && !answered,
        }
    }

    /// The row of a run in flight. A start marker already there was left by
    /// an interrupted run, which counts as a failure. The run is the owner's
    /// when `owner_pass` says so, when the owner's request is still pending,
    /// or when it goes on from an owner's run that has not finished; it stays
    /// the owner's until a run of it ends complete with nothing failed.
    pub(super) fn started(self, start: u64, owner_pass: bool) -> Self {
        let failures = if self.started_at.is_some() {
            self.failures.saturating_add(1)
        } else {
            self.failures
        };
        Self {
            started_at: Some(start),
            failures,
            owners: owner_pass || self.requested_at.is_some() || self.owners,
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

    /// Whether the run in flight answers an owner's request.
    pub(super) const fn owners(&self) -> bool {
        self.owners
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
/// one whose run was interrupted or failed, else its stored due time or the
/// earliest deadline a door noted for it, whichever is first; never later than
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
    // A noted deadline makes the sweep due then, unless it is backing off.
    if state.failures == 0 {
        let txn = vault.store.env.read_txn()?;
        if let Some(noted) = super::wake::earliest_in_txn(&vault.store, &txn, sweep)? {
            return Ok(noted.min(state.next_due_at));
        }
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

/// Whether any erasure obligation (an `h:` row, or a `hw:` withdrawn
/// generation's) is queued.
pub(super) fn erase_obligation_waiting(vault: &Vault) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    for prefix in [HARD_ERASE_SWEEP_PREFIX, WITHDRAWN_GENERATION_SWEEP_PREFIX] {
        let mut rows = vault.store.sync_queue.prefix_iter(&txn, prefix)?;
        if rows.next().transpose()?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}
