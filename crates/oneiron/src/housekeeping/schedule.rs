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
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SweepState {
    /// When the sweep is next due.
    next_due_at: u64,
    /// When its last run ended; 0 before the first.
    finished_at: u64,
    /// When a run in flight started.
    started_at: Option<u64>,
    /// Runs in a row that failed, panicked or were interrupted.
    failures: u32,
}

impl SweepState {
    pub(super) fn succeeded(end: u64, next_due_at: u64) -> Self {
        Self {
            next_due_at,
            finished_at: end,
            started_at: None,
            failures: 0,
        }
    }

    /// The row of a run in flight. A start marker already there was left by
    /// an interrupted run, which counts as a failure.
    pub(super) fn started(self, start: u64) -> Self {
        let failures = if self.started_at.is_some() {
            self.failures.saturating_add(1)
        } else {
            self.failures
        };
        Self {
            started_at: Some(start),
            failures,
            ..self
        }
    }

    pub(super) fn failed(self, end: u64, every: u64) -> Self {
        let failures = self.failures.saturating_add(1);
        Self {
            next_due_at: end.saturating_add(retry_after(failures, every)),
            finished_at: end,
            started_at: None,
            failures,
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
/// one whose run was interrupted, else its stored due time.
pub(super) fn due_at(
    vault: &Vault,
    sweep: HousekeepingSweep,
    state: Option<&SweepState>,
    every: u64,
) -> Result<u64> {
    let Some(state) = state else {
        return Ok(0);
    };
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
    state: SweepState,
) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    SCHEDULE.put(&vault.store, &mut txn, &sweep.code().to_owned(), &state)?;
    txn.commit()?;
    Ok(())
}

/// Whether any erasure obligation (an `h:` row) is queued.
fn erase_obligation_waiting(vault: &Vault) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let mut rows = vault
        .store
        .sync_queue
        .prefix_iter(&txn, HARD_ERASE_SWEEP_PREFIX)?;
    Ok(rows.next().transpose()?.is_some())
}
