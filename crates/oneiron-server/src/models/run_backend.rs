//! A ladder as an [`LlmBackend`], for engine code that calls a backend
//! itself (the Dreamer's step layer). Each call is admitted under the run on
//! its own permits and sent through the run's gate. The caller's lease is
//! the caller's own meter's business; this backend never dispatches on it.
use std::sync::Arc;

use oneiron::llm::run_admission::RunAdmission;
use oneiron::{
    BudgetLease, LlmBackend, LlmCapability, LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId,
};

use super::OfferLadder;

pub struct RunBackend {
    ladder: Arc<OfferLadder>,
    run: RunAdmission,
}

impl RunBackend {
    #[must_use]
    pub fn new(ladder: Arc<OfferLadder>, run: RunAdmission) -> Self {
        Self { ladder, run }
    }
}

impl LlmBackend for RunBackend {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.ladder.supports(model, &capability)
    }

    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        Box::pin(self.ladder.generate(&self.run, request, None))
    }

    fn stream<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.ladder.stream(&self.run, request, None)
    }
}
