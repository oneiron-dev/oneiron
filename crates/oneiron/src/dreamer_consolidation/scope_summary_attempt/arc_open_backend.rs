//! Observes whether one advisory durable generation actually called its backend.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::EntityId;
use oneiron_model::llm::{
    BudgetLease, LlmBackend, LlmCapability, LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId,
};

pub(super) struct FreshBackend<'a> {
    pub(super) inner: &'a dyn LlmBackend,
    pub(super) fresh: AtomicBool,
}

impl LlmBackend for FreshBackend<'_> {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.inner.supports(model, capability)
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            self.fresh.store(true, Ordering::Relaxed);
            self.inner.generate(request, lease).await
        })
    }

    fn generate_sourced<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
        sources: Option<Vec<EntityId>>,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            self.fresh.store(true, Ordering::Relaxed);
            self.inner.generate_sourced(request, lease, sources).await
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.inner.stream(request, lease)
    }
}
