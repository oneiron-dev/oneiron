//! Routing views selected by the native run's receipt posture.

use super::*;

impl OfferLadder {
    /// Settles a rung that did not answer, and says whether it went out. One
    /// that started keeps its reservation as spend; one admitted and never sent
    /// never started its lease, so its reservation is released and it pays
    /// nothing. A settlement the meter refuses is on the run's `Settled` row.
    pub(super) fn settle_failed(&self, permit: RunPermit) -> bool {
        let sent = permit.dispatched();
        if let Err(denied) = permit.settle(CallOutcome::Failed) {
            if !self.rests.is_unrecorded() {
                tracing::error!(%denied, "a failed rung's settlement was refused");
            }
        }
        sent
    }

    /// A fresh routing view only for a core-owned unrecorded run. The caller
    /// must still perform its normal route and role admission first.
    pub(crate) fn for_run(self: &Arc<Self>, run: &RunAdmission) -> Arc<Self> {
        if !run.is_unrecorded() {
            return Arc::clone(self);
        }
        Arc::new(self.with_rests(self.rests.unrecorded_view()))
    }

    fn with_rests(&self, rests: Arc<OfferCooldowns>) -> Self {
        Self {
            name: self.name.clone(),
            rungs: self.rungs.clone(),
            picked: self.picked,
            rests,
            scope: self.scope,
            prefix: self.prefix.clone(),
            listed: self.listed.clone(),
        }
    }

    /// Rewrap at traversal, not construction: configured fallback graphs
    /// can contain cycles. Every target shares this call's local rests.
    pub(super) fn fallback_view(&self, target: Arc<Self>) -> Arc<Self> {
        if self.rests.is_unrecorded() {
            Arc::new(target.with_rests(Arc::clone(&self.rests)))
        } else {
            target
        }
    }
}
