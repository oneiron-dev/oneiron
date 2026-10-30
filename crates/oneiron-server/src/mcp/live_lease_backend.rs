//! A backend read live on its spend scope (FIX 11457): for a run outside
//! the step pump that spends on a meter its scope bounds, each call first
//! takes the lease's look ([`LiveLease::book_and_revise`]), as the pump's
//! own calls do, so it is admitted against what the scope has left then,
//! its siblings' spend included. The lease is the one ledger: this backend
//! books nothing itself.

use oneiron::{
    BudgetLease, LlmBackend, LlmCapability, LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId,
};

use crate::ai_host::live_lease::LiveLease;

/// `inner` on `live`'s meter, each call after the lease's look: a call the
/// revised limit no longer fits is refused by `inner`'s own admission on
/// that meter, as a spent meter refuses it.
pub(crate) struct LiveLeaseBackend<'l> {
    live: &'l LiveLease<'l>,
    inner: &'l dyn LlmBackend,
}

impl<'l> LiveLeaseBackend<'l> {
    /// `inner`, a backend whose calls spend on `live`'s meter.
    pub(crate) fn new(live: &'l LiveLease<'l>, inner: &'l dyn LlmBackend) -> Self {
        Self { live, inner }
    }
}

impl LlmBackend for LiveLeaseBackend<'_> {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.inner.supports(model, capability)
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.live.book_and_revise();
        self.inner.generate(request, lease)
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.live.book_and_revise();
        self.inner.stream(request, lease)
    }
}
