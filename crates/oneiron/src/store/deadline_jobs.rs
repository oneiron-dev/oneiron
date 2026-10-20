//! Deadline jobs (SCAN C030): the recalls and searches a door answers at
//! their deadline, counted per caller on the vault while their work runs, the
//! work left after the door answered included. Past
//! `limits.deadline_jobs_per_caller` a new one is refused, typed and naming
//! the row; none is queued or dropped.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::limit_ask::EngineLimit;
use crate::memory::{MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult};

/// The deadline jobs each caller has running on one vault.
#[derive(Default)]
pub(crate) struct DeadlineJobs(Arc<Mutex<BTreeMap<EntityId, u64>>>);

/// One running deadline job's place among its caller's: held by the job's
/// work until it ends, and freed when dropped.
#[must_use = "a deadline job counts only while its place is held"]
pub struct DeadlineJob {
    caller: EntityId,
    running: Arc<Mutex<BTreeMap<EntityId, u64>>>,
}

impl Drop for DeadlineJob {
    fn drop(&mut self) {
        let mut running = lock(&self.running);
        if let Some(count) = running.get_mut(&self.caller) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                running.remove(&self.caller);
            }
        }
    }
}

impl Vault {
    /// `caller`'s place for one more deadline job: a recall or search whose
    /// door answers at its deadline and may leave its work running past the
    /// answer. Hold it in the job's work until that work ends.
    ///
    /// # Errors
    ///
    /// `INVALID_STATE` naming `limits.deadline_jobs_per_caller` when `caller`
    /// already runs as many as the row is set to; the row asks first.
    pub fn admit_deadline_job(&self, caller: EntityId) -> MemoryResult<DeadlineJob> {
        let jobs = &self.store.deadline_jobs.0;
        let mut running = lock(jobs);
        let held = running.get(&caller).copied().unwrap_or(0);
        let measured = held.saturating_add(1);
        if let Some(bound) = self.measure_limit(EngineLimit::DeadlineJobsPerCaller, measured) {
            return Err(deadline_jobs_refused(bound));
        }
        running.insert(caller, measured);
        Ok(DeadlineJob {
            caller,
            running: Arc::clone(jobs),
        })
    }
}

/// The refusal of a deadline job past its caller's row.
fn deadline_jobs_refused(bound: u64) -> MemoryError {
    let row = EngineLimit::DeadlineJobsPerCaller.key();
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("{row}: this caller already runs {bound} deadline jobs"),
        &[
            "Retry once an earlier recall or search under a deadline has ended, or raise the row.",
        ],
    )
}

/// The counts change in one step each, so a holder that panicked left them
/// whole: a poisoned lock is still true.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
