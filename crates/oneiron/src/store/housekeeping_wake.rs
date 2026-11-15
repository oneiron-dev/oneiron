//! Wake deadlines: when a retirement sweep next has work.
//!
//! A door that starts a retirement deadline notes it here in its own write
//! transaction: a secret lease's expiry, a voice print's retention deadline, a
//! critical confirm's window. Each note arms one row of the sweep's deadline
//! job, a one-time job at the deadline about a fresh id, so two notes of the
//! same deadline are two rows, and the schedule's due index is the only index
//! of them (DESIGN 15-setting-primitive, stage 5b). The note also makes the
//! sweep's job due by its deadline. A run that covered deadlines disarms
//! exactly the rows it listed before it started; a row noted since stays for
//! the next run. A row whose time comes before a run covered it runs: it makes
//! the sweep due and waits for the run that covers it. A deadline that moved or
//! was settled early leaves a row that costs one run that finds nothing.
//!
//! Live-body edits also note the annotation follow sweep as due for the next
//! running-host pass. That sweep's deadlines do not wake a stopped vault.

use heed::RwTxn;

use crate::EntityId;
use crate::Vault;
use crate::error::Result;
use crate::housekeeping::jobs::{deadline_job, sweep_due_by_in_txn};
use crate::schedule::Trigger;
use crate::store::Store;
use crate::store::housekeeping_schedule::HousekeepingSweep;

/// Deadlines one covering run disarms at most; the rest go with the next run.
const CLEAR_LIMIT: usize = 4096;

/// Notes that `sweep` has work due at `at`, in the caller's transaction, so
/// the note commits with the deadline it records: it arms a row of the sweep's
/// deadline job at `at`, and makes the sweep's job due by then unless it is
/// backing off. A sweep without deadlines notes nothing.
pub(crate) fn note_wake_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    sweep: HousekeepingSweep,
    at: u64,
) -> Result<()> {
    let Some(deadline) = deadline_job(sweep) else {
        return Ok(());
    };
    let id = store.clock.entity_id()?;
    crate::schedule::arm_in_txn(store, txn, deadline, Some(id), Trigger::At { at })?;
    sweep_due_by_in_txn(store, txn, sweep, at)
}

/// The deadlines of `sweep` due by `now`, as they stand before a run starting
/// now: each one's id and time.
pub(crate) fn due_by(
    vault: &Vault,
    sweep: HousekeepingSweep,
    now: u64,
) -> Result<Vec<(EntityId, u64)>> {
    let Some(deadline) = deadline_job(sweep) else {
        return Ok(Vec::new());
    };
    let txn = vault.store.env.read_txn()?;
    crate::schedule::deadlines_in_txn(&vault.store, &txn, deadline.code, now, CLEAR_LIMIT)
}

/// Disarms the deadlines of `sweep` a covering run listed before it started.
pub(crate) fn clear(
    vault: &Vault,
    sweep: HousekeepingSweep,
    covered: &[(EntityId, u64)],
) -> Result<()> {
    let Some(deadline) = deadline_job(sweep) else {
        return Ok(());
    };
    if covered.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|txn| {
        for (id, _) in covered {
            crate::schedule::disarm_in_txn(&vault.store, txn, deadline.code, Some(*id))?;
        }
        Ok(())
    })
}
