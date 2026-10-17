//! The voice call's backend for the host's own model calls (OF-410): partial
//! enrichment and the sentence safeguard's model. Each request goes to the
//! ladder that serves its exact model on this server, authorized as the raw
//! inference door authorizes an advertised model, and runs on the call's
//! run, which charges the call's line. A model no rung serves is refused
//! before anything is sent; no other model stands in for it.

use std::sync::Arc;

use oneiron::llm::run_admission::RunAdmission;
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::{
    BudgetLease, FatalLlmError, LlmBackend, LlmCapability, LlmGenerateFuture, LlmRequest,
    LlmResult, LlmStreamResult, ModelId,
};

use crate::models::{ModelRouter, OfferLadder};
use crate::server::SyncServer;

pub(super) struct CallBackend {
    server: Arc<SyncServer>,
    router: Arc<ModelRouter>,
    run: RunAdmission,
}

impl CallBackend {
    pub(super) fn new(
        server: Arc<SyncServer>,
        router: Arc<ModelRouter>,
        run: RunAdmission,
    ) -> Self {
        Self {
            server,
            router,
            run,
        }
    }

    /// The ladder serving the request's model, and the request as the vault
    /// authorizes it there.
    fn authorized(&self, request: LlmRequest) -> LlmResult<(Arc<OfferLadder>, LlmRequest)> {
        let (locality, ladder) = self
            .router
            .served(&request.model)
            .ok_or(FatalLlmError::InvalidRequest)?;
        let context = HostInferenceContext {
            binding: HostInferenceBinding::Advertised {
                model: request.model.clone(),
                locality,
            },
            extraction_egress: self.server.extraction_egress.as_deref(),
        };
        let request = self
            .server
            .vault()
            .authorize_raw_inference(request, &context)
            .map_err(|_| FatalLlmError::InvalidRequest)?
            .into_request();
        Ok((ladder, request))
    }
}

impl LlmBackend for CallBackend {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.router
            .served(model)
            .is_some_and(|(_, ladder)| ladder.supports(model, &capability))
    }

    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let (ladder, request) = self.authorized(request)?;
            ladder.generate(&self.run, request, None).await
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        let (ladder, request) = self.authorized(request)?;
        ladder.stream(&self.run, request, None)
    }
}
