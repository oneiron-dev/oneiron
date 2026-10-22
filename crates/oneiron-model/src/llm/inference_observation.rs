//! What each physical inference request measured, published by the adapter that
//! sends it while the request is alive (FIX 9065), so a call that fails, is cancelled
//! or is dropped still settles the evidence it produced.
//!
//! A [`BudgetLease`](super::BudgetLease) carries one collector, which its clones
//! share. An adapter begins one observation per physical request it sends
//! ([`BudgetLease::begin_inference_observation`](super::BudgetLease::begin_inference_observation))
//! and updates it in place
//! ([`BudgetLease::observe_inference_call`](super::BudgetLease::observe_inference_call)):
//! a partial record while the request runs, its final receipt when it returns. Two
//! physical requests are two observations even when their records are equal; nothing
//! is merged by content. A count or time no native source measured stays absent, never
//! zero, as on every [`InferenceCallReceipt`]. The collector changes no admission and
//! no charge.

use std::sync::{Arc, Mutex, PoisonError};

use super::InferenceCallReceipt;

/// One physical request's observation on the lease that began it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InferenceObservationId {
    /// The collector that issued it, by address: another lease's id is ignored.
    collector: usize,
    index: usize,
}

/// What one physical request measured, as far as it got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferenceCallObservation {
    /// The measured progress of a request that has not returned: in flight, or cut
    /// before it could.
    Partial(InferenceCallReceipt),
    /// The request's final receipt: the one its answer's usage also carries.
    Final(InferenceCallReceipt),
}

impl InferenceCallObservation {
    /// The receipt the observation holds.
    #[must_use]
    pub fn receipt(&self) -> &InferenceCallReceipt {
        match self {
            Self::Partial(receipt) | Self::Final(receipt) => receipt,
        }
    }

    /// The receipt, owned.
    #[must_use]
    pub fn into_receipt(self) -> InferenceCallReceipt {
        match self {
            Self::Partial(receipt) | Self::Final(receipt) => receipt,
        }
    }

    /// Whether the request returned its final receipt.
    #[must_use]
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Final(_))
    }
}

/// One lease's observations, in the order their requests began; a slot stays empty
/// until its request records something.
#[derive(Default)]
pub(crate) struct InferenceObservations {
    calls: Mutex<Vec<Option<InferenceCallObservation>>>,
}

impl InferenceObservations {
    fn calls(&self) -> std::sync::MutexGuard<'_, Vec<Option<InferenceCallObservation>>> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn begin(self: &Arc<Self>) -> InferenceObservationId {
        let mut calls = self.calls();
        calls.push(None);
        InferenceObservationId {
            collector: Arc::as_ptr(self) as usize,
            index: calls.len() - 1,
        }
    }

    /// Puts `observation` in `id`'s slot. A final receipt is kept against a later
    /// partial one; an id this collector did not issue is ignored.
    pub(crate) fn observe(
        self: &Arc<Self>,
        id: InferenceObservationId,
        observation: InferenceCallObservation,
    ) {
        if id.collector != Arc::as_ptr(self) as usize {
            return;
        }
        let mut calls = self.calls();
        let Some(slot) = calls.get_mut(id.index) else {
            return;
        };
        if slot
            .as_ref()
            .is_some_and(InferenceCallObservation::is_final)
            && !observation.is_final()
        {
            return;
        }
        *slot = Some(observation);
    }

    pub(crate) fn snapshot(&self) -> Vec<InferenceCallObservation> {
        self.calls().iter().flatten().cloned().collect()
    }
}
