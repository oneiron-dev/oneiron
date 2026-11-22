//! The Dreamer's routes as this server sends on them, each able to send one
//! call under the rows the engine read that call's input from (FIX 6998):
//! the route's run, bound for that call alone through
//! [`RunAdmission::sourced`], so the call's permit and its metered
//! settlement carry them. A call the engine names no complete set for sends
//! on the route's own run, its sources unknown. A call bound to its rows
//! asks them in the vault before each rung, wait and resend, and at each
//! physical send, and sends nothing once one is withdrawn ([`SourceFence`],
//! [DREAMER-STEP-RESENDS-ERASED-SOURCE-WORDS]).
use std::sync::Arc;

use oneiron::dreamer_consolidation::SourcedBackend;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::llm::{FatalLlmError, LlmError};
use oneiron::{
    BudgetLease, EntityId, LlmBackend, LlmCapability, LlmGenerateFuture, LlmRequest,
    LlmStreamResult, ModelId, Vault,
};

use crate::models::{OfferLadder, RunBackend, SourceFence};

/// A ladder on a run, as [`RunBackend`] sends on it, that lends each call
/// the same run bound to that call's rows, fenced by them in `vault`.
pub(super) struct SourcedRunBackend {
    ladder: Arc<OfferLadder>,
    run: RunAdmission,
    vault: Arc<Vault>,
}

impl SourcedRunBackend {
    pub(super) fn new(ladder: Arc<OfferLadder>, run: RunAdmission, vault: Arc<Vault>) -> Self {
        Self { ladder, run, vault }
    }
}

impl LlmBackend for SourcedRunBackend {
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

impl SourcedBackend for SourcedRunBackend {
    fn sourced(&self, rows: Vec<EntityId>) -> Box<dyn LlmBackend + '_> {
        let fence = SourceFence::new(Arc::clone(&self.vault), rows.clone());
        Box::new(
            RunBackend::new(Arc::clone(&self.ladder), self.run.sourced(Some(rows)))
                .within_source_fence(fence),
        )
    }
}

/// A TASK realization's backend: the task route's ladder on its role's run,
/// sending as the route's own backend does, and keeping the model of the
/// rung that answered, fallback included. A call it lends under its rows
/// keeps that model here too.
pub(super) struct ServedRealization {
    ladder: Arc<OfferLadder>,
    run: RunAdmission,
    vault: Arc<Vault>,
    served: std::sync::Mutex<Option<ModelId>>,
}

impl ServedRealization {
    pub(super) fn new(ladder: Arc<OfferLadder>, run: RunAdmission, vault: Arc<Vault>) -> Self {
        Self {
            ladder,
            run,
            vault,
            served: std::sync::Mutex::new(None),
        }
    }

    /// The model of the rung that answered last, if one did.
    pub(super) fn served(self) -> Option<ModelId> {
        self.served
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// One generation on `run`, keeping the model that answered; under
    /// `fence`, asked first and before each rung, wait and resend.
    fn generate_on<'a>(
        &'a self,
        run: &'a RunAdmission,
        request: LlmRequest,
        fence: Option<&'a SourceFence>,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let may_send = || fence.is_none_or(SourceFence::stands);
            if !may_send() {
                return Err(LlmError::from(FatalLlmError::InvalidRequest));
            }
            let generated = self
                .ladder
                .generate_served_while(run, request, None, &may_send)
                .await;
            generated.map(|(response, served)| {
                *self.served.lock().expect("served model mutex poisoned") = Some(served);
                response
            })
        })
    }
}

impl LlmBackend for ServedRealization {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.ladder.supports(model, &capability)
    }

    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        self.generate_on(&self.run, request, None)
    }

    fn stream<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.ladder.stream(&self.run, request, None)
    }
}

impl SourcedBackend for ServedRealization {
    fn sourced(&self, rows: Vec<EntityId>) -> Box<dyn LlmBackend + '_> {
        let fence = SourceFence::new(Arc::clone(&self.vault), rows.clone());
        Box::new(SourcedRealization {
            realization: self,
            run: self
                .run
                .sourced(Some(rows))
                .within_text_dispatch_release(fence.release()),
            fence,
        })
    }
}

/// One realization call on its run bound to its rows, fenced by them.
struct SourcedRealization<'r> {
    realization: &'r ServedRealization,
    run: RunAdmission,
    fence: SourceFence,
}

impl LlmBackend for SourcedRealization<'_> {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.realization.supports(model, capability)
    }

    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        self.realization
            .generate_on(&self.run, request, Some(&self.fence))
    }

    fn stream<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.realization.ladder.stream(&self.run, request, None)
    }
}
