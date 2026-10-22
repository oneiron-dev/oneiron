//! One physical request's observation, published by the adapter that sends
//! it while the request is alive (FIX 9417).
//!
//! An adapter begins one [`InferencePublisher`] at the physical send (never
//! once more at a wrapper above it), records what the request has measured
//! so far as it learns it, and its final receipt once the request returned
//! the answer that receipt rides in. A request cut, failed or dropped keeps
//! the last measurement it recorded: the lease's collector holds it, and
//! dropping the publisher changes nothing. Nothing a native source did not
//! measure is recorded, as on every [`InferenceCallReceipt`]: no count or
//! time is made up from chunks or the client's clock.

use super::{BudgetLease, InferenceCallObservation, InferenceCallReceipt, InferenceObservationId};

/// One physical request's observation on its call's lease.
pub struct InferencePublisher {
    lease: BudgetLease,
    id: InferenceObservationId,
}

impl std::fmt::Debug for InferencePublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InferencePublisher")
            .field("lease", &self.lease.id())
            .finish_non_exhaustive()
    }
}

impl InferencePublisher {
    /// Begins the observation of one physical request `lease`'s call sends,
    /// before it leaves.
    #[must_use]
    pub fn begin(lease: &BudgetLease) -> Self {
        Self {
            id: lease.begin_inference_observation(),
            lease: lease.clone(),
        }
    }

    /// Records what the request has measured so far, in place of what it
    /// recorded before: kept if the request never returns.
    pub fn partial(&self, receipt: InferenceCallReceipt) {
        self.lease
            .observe_inference_call(self.id, InferenceCallObservation::Partial(receipt));
    }

    /// Records the request's final receipt: the one the answer it returned
    /// carries in its usage.
    pub fn finish(&self, receipt: InferenceCallReceipt) {
        self.lease
            .observe_inference_call(self.id, InferenceCallObservation::Final(receipt));
    }
}
