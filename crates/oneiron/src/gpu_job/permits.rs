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

/// The live chunks' permits, each under its job and the idempotency key of
/// the chunk it pays. A job can hold two for a moment: a chunk whose end has
/// written its settlement keeps its permit until that end settles it, while a
/// resume already holds the next chunk's. Dropped, it hands every permit off
/// as [`CallOutcome::Kept`]: a host shutdown never charges a running job's
/// reservation as a failed call.
#[derive(Default)]
pub struct GpuJobPermits {
    live: Mutex<HashMap<EntityId, Vec<HeldPermit>>>,
    /// The gates a test set for the next end of a job's chunk
    /// (`test_doors::gpu_job`). Held per host, so no test shares them.
    #[cfg(oneiron_test_support)]
    pub(crate) end_commit_gates: Mutex<Vec<(EntityId, std::sync::Arc<std::sync::Barrier>)>>,
}

/// One chunk's permit and the idempotency key of that chunk.
struct HeldPermit {
    chunk_key: String,
    permit: RunPermit,
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

    /// The jobs for whose chunks this host holds a permit.
    #[must_use]
    pub fn jobs(&self) -> Vec<EntityId> {
        self.lock().keys().copied().collect()
    }

    /// Whether this host holds a permit for one of the job's chunks.
    #[must_use]
    pub fn holds(&self, job: &EntityId) -> bool {
        self.lock().contains_key(job)
    }

    /// Whether this host holds the permit of the job's chunk under
    /// `chunk_key`.
    pub(super) fn holds_chunk(&self, job: &EntityId, chunk_key: &str) -> bool {
        self.lock()
            .get(job)
            .is_some_and(|held| held.iter().any(|held| held.chunk_key == chunk_key))
    }

    /// Hands every permit off without a charge, for a host about to stop.
    /// Returns each job with the settlement of each of its permits.
    pub fn hand_off_all(&self) -> Vec<(EntityId, Result<BudgetSettlement, RunDenied>)> {
        let permits: Vec<_> = self.lock().drain().collect();
        permits
            .into_iter()
            .flat_map(|(job, held)| {
                held.into_iter()
                    .map(move |held| (job, held.permit.settle(CallOutcome::Kept)))
            })
            .collect()
    }

    /// Holds `permit` for the job's chunk under `chunk_key`. Another chunk's
    /// permit stays held: it settles at that chunk's own end. A permit held
    /// again for the same chunk replaces the first without charging it.
    pub(super) fn hold(&self, job: EntityId, chunk_key: String, permit: RunPermit) {
        let previous = {
            let mut live = self.lock();
            let held = live.entry(job).or_default();
            let previous = held
                .iter()
                .position(|held| held.chunk_key == chunk_key)
                .map(|at| held.remove(at));
            held.push(HeldPermit { chunk_key, permit });
            previous
        };
        if let Some(previous) = previous {
            let _ = previous.permit.settle(CallOutcome::Kept);
        }
    }

    /// The permit of the job's chunk under `chunk_key`: another chunk's
    /// permit stays held.
    pub(super) fn take_for_chunk(&self, job: &EntityId, chunk_key: &str) -> Option<RunPermit> {
        let mut live = self.lock();
        let held = live.get_mut(job)?;
        let at = held.iter().position(|held| held.chunk_key == chunk_key)?;
        let taken = held.remove(at);
        if held.is_empty() {
            live.remove(job);
        }
        Some(taken.permit)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<EntityId, Vec<HeldPermit>>> {
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
