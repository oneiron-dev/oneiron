//! Routing views selected by the native run's receipt posture.

use super::*;

impl OfferLadder {
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
