//! Deadline jobs (SCAN C030): the recalls and searches a door answers at
//! their deadline, counted per caller on the vault while their work runs, the
//! work left after the door answered included. Past
//! `limits.deadline_jobs_per_caller` the job runs on, and its caller raises
//! the typed `deadline_jobs_high` check, once per caller per window: never a
//! refusal, a queue or a drop (rule 5).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::limit_ask::EngineLimit;

/// The typed check a caller past `limits.deadline_jobs_per_caller` raises.
pub const DEADLINE_JOBS_CHECK_KIND: &str = "deadline_jobs_high";

/// How long one caller's check stands before the same caller raises it again:
/// the window a `[limits]` question counts its crossings in.
pub const DEADLINE_JOBS_CHECK_WINDOW: Duration = Duration::from_secs(60);

/// The deadline jobs each caller has running on one vault, and when each
/// caller last raised its check.
#[derive(Default)]
pub struct DeadlineJobs {
    pub running: Arc<Mutex<BTreeMap<EntityId, u64>>>,
    pub checked: Mutex<BTreeMap<EntityId, Instant>>,
}

impl DeadlineJobs {
    /// Whether `caller` raises its check at `now`: it raised none in the
    /// window. Checks past the window are let go.
    pub fn check_due(&self, caller: EntityId, now: Instant) -> bool {
        let mut checked = lock(&self.checked);
        checked.retain(|_, at| now.saturating_duration_since(*at) < DEADLINE_JOBS_CHECK_WINDOW);
        if checked.contains_key(&caller) {
            return false;
        }
        checked.insert(caller, now);
        true
    }
}

/// One running deadline job's place among its caller's: held by the job's
/// work until it ends, and freed when dropped.
#[must_use = "a deadline job counts only while its place is held"]
pub struct DeadlineJob {
    pub caller: EntityId,
    pub running: Arc<Mutex<BTreeMap<EntityId, u64>>>,
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

/// The counts change in one step each, so a holder that panicked left them
/// whole: a poisoned lock is still true.
pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
