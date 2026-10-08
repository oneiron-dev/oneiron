//! A backend over every configured model and seat, chosen by the request's
//! own model id: the raw `/v1/llm` routes call whichever model they name.
use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::{
    BudgetLease, FatalLlmError, LlmBackend, LlmCapability, LlmGenerateFuture, LlmRequest,
    LlmStreamResult, ModelId, ModelLocality,
};

#[derive(Default)]
pub struct ModelRouter {
    routes: BTreeMap<ModelId, (ModelLocality, Arc<dyn LlmBackend>)>,
}

impl ModelRouter {
    pub(super) fn insert(
        &mut self,
        model: ModelId,
        locality: ModelLocality,
        backend: Arc<dyn LlmBackend>,
    ) {
        self.routes.insert(model, (locality, backend));
    }

    pub(super) fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Where `model` runs, when this router serves it. This is the host's
    /// attestation for the engine's inference admission.
    pub fn locality(&self, model: &ModelId) -> Option<ModelLocality> {
        self.routes.get(model).map(|(locality, _)| *locality)
    }

    fn backend(&self, model: &ModelId) -> Option<&Arc<dyn LlmBackend>> {
        self.routes.get(model).map(|(_, backend)| backend)
    }
}

impl LlmBackend for ModelRouter {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.backend(model)
            .is_some_and(|backend| backend.supports(model, capability))
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        match self.backend(&request.model) {
            Some(backend) => backend.generate(request, lease),
            None => Box::pin(async { Err(FatalLlmError::InvalidRequest.into()) }),
        }
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        match self.backend(&request.model) {
            Some(backend) => backend.stream(request, lease),
            None => Err(FatalLlmError::InvalidRequest.into()),
        }
    }
}
