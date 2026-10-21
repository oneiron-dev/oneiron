//! A rung's managed worker (FIX 8315, DESIGN-V2 R2): the call waits for it
//! and holds its lease from before admission through settlement or
//! cancellation.
//!
//! A worker that is starting, backing off or stopped for idleness makes the
//! call wait, with no deadline: no room means wait, never a silent fallback.
//! Only a parked worker (failed, unverified or retired) gives up the call,
//! as the failure an unreachable provider gives today, so the rungs after it
//! serve as they always would. A rung no managed worker serves, and every
//! rung in a process that launches none, is untouched.
use oneiron_driver::{InferenceWorker, WorkerLease};

use super::*;

impl OfferLadder {
    /// The managed worker the rung at `index` is bound to, by its row's
    /// provider and wire model, when this process launches it.
    pub(super) fn managed_worker(&self, index: usize) -> Option<InferenceWorker> {
        let rung = &self.rungs[index];
        super::super::worker_host::managed_worker(&rung.provider, &rung.wire_model)
    }

    /// Waits for the rung's managed worker to be ready and holds it; `None`
    /// for a rung no managed worker serves. A parked worker's call fails as
    /// an unreachable provider's does.
    pub(super) async fn hold_worker(&self, index: usize) -> LlmResult<Option<WorkerLease>> {
        let Some(worker) = self.managed_worker(index) else {
            return Ok(None);
        };
        match worker.acquire().await {
            Ok(lease) => Ok(Some(lease)),
            Err(unavailable) => {
                tracing::warn!(
                    rung = self.rungs[index].position,
                    %unavailable,
                    "the rung's managed worker is parked; the call goes on as for a provider that is down"
                );
                Err(RetryableLlmError::StreamCut.into())
            }
        }
    }

    /// The rung's probation permit (OF-305), or none needed for a managed
    /// worker, whose supervisor says when it serves; `None` when the rung is
    /// passed.
    pub(super) fn probe_unless_managed(
        &self,
        index: usize,
        walk: &mut Walk,
    ) -> Option<Option<ProbePermit>> {
        if self.managed_worker(index).is_some() {
            return Some(None);
        }
        self.probe(index, walk).map(Some)
    }
}
