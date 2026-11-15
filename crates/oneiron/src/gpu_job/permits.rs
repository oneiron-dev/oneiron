//! The permits of the chunks a host runs, held in memory between steps. A
//! permit cannot be stored; the job's record keeps its facts. A host that
//! stops hands each one off without a charge ([`CallOutcome::Kept`]), and the
//! step after its restart admits the chunk again, so the new permit pays the
//! chunk's end (the kept-job precedent of media and training runs).
use std::collections::HashMap;
use std::sync::Mutex;

use crate::EntityId;
use crate::llm::BudgetSettlement;
use crate::llm::run_admission::{CallOutcome, RunDenied, RunPermit};

/// The live chunks' permits, one per job. Dropped, it hands every permit off
/// as [`CallOutcome::Kept`]: a host shutdown never charges a running job's
/// reservation as a failed call.
#[derive(Default)]
pub struct GpuJobPermits {
    live: Mutex<HashMap<EntityId, RunPermit>>,
}

impl std::fmt::Debug for GpuJobPermits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpuJobPermits")
            .field("live", &self.jobs())
            .finish()
    }
}

impl GpuJobPermits {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The jobs whose chunk permit this host holds.
    #[must_use]
    pub fn jobs(&self) -> Vec<EntityId> {
        self.lock().keys().copied().collect()
    }

    #[must_use]
    pub fn holds(&self, job: &EntityId) -> bool {
        self.lock().contains_key(job)
    }

    /// Hands every permit off without a charge, for a host about to stop.
    /// Returns each job with its settlement.
    pub fn hand_off_all(&self) -> Vec<(EntityId, Result<BudgetSettlement, RunDenied>)> {
        let permits: Vec<_> = self.lock().drain().collect();
        permits
            .into_iter()
            .map(|(job, permit)| (job, permit.settle(CallOutcome::Kept)))
            .collect()
    }

    pub(super) fn hold(&self, job: EntityId, permit: RunPermit) {
        let previous = self.lock().insert(job, permit);
        if let Some(previous) = previous {
            // One chunk runs at a time; a second permit for the job replaces
            // the first without charging it.
            let _ = previous.settle(CallOutcome::Kept);
        }
    }

    pub(super) fn take(&self, job: &EntityId) -> Option<RunPermit> {
        self.lock().remove(job)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<EntityId, RunPermit>> {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for GpuJobPermits {
    fn drop(&mut self) {
        let _ = self.hand_off_all();
    }
}
