//! Shared backend fixture for deadline-driven consolidation tests.
use super::*;

/// Advances the wake clock only when the selected provider response arrives.
pub(super) struct ExpiringBackend {
    pub(super) inner: ScriptedBackend,
    pub(super) clock: std::sync::Arc<AtomicU64>,
    pub(super) expire_on_call: usize,
    pub(super) expiry_elapsed_ms: u64,
    pub(super) calls: AtomicUsize,
    pub(super) native_json: bool,
}

impl LlmBackend for ExpiringBackend {
    fn supports(&self, _: &crate::ModelId, capability: crate::LlmCapability) -> bool {
        self.native_json && capability == crate::LlmCapability::JsonResponse
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        Box::pin(async move {
            let response = self.inner.generate(request, lease).await;
            if call == self.expire_on_call {
                self.clock.store(self.expiry_elapsed_ms, Ordering::SeqCst);
            }
            response
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(crate::LlmError::Fatal(crate::FatalLlmError::InvalidRequest))
    }
}
