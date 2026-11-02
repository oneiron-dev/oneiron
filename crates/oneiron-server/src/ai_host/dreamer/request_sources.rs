//! The Dreamer's routes as this server sends on them, each able to send one
//! call under the rows the engine read that call's input from (FIX 6998):
//! the route's run, bound for that call alone through
//! [`RunAdmission::sourced`], so the call's permit and its metered
//! settlement carry them. A call the engine names no complete set for sends
//! on the route's own run, its sources unknown.
use std::sync::Arc;

use oneiron::dreamer_consolidation::SourcedBackend;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::{
    BudgetLease, EntityId, LlmBackend, LlmCapability, LlmGenerateFuture, LlmRequest,
    LlmStreamResult, ModelId,
};

use crate::models::{OfferLadder, RunBackend};

/// A ladder on a run, as [`RunBackend`] sends on it, that lends each call
/// the same run bound to that call's rows.
pub(super) struct SourcedRunBackend {
    ladder: Arc<OfferLadder>,
    run: RunAdmission,
}

impl SourcedRunBackend {
    pub(super) fn new(ladder: Arc<OfferLadder>, run: RunAdmission) -> Self {
        Self { ladder, run }
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
        Box::new(RunBackend::new(
            Arc::clone(&self.ladder),
            self.run.sourced(Some(rows)),
        ))
    }
}

/// A TASK realization's backend: the task route's ladder on its role's run,
/// sending as the route's own backend does, and keeping the model of the
/// rung that answered, fallback included. A call it lends under its rows
/// keeps that model here too.
pub(super) struct ServedRealization {
    ladder: Arc<OfferLadder>,
    run: RunAdmission,
    served: std::sync::Mutex<Option<ModelId>>,
}

impl ServedRealization {
    pub(super) fn new(ladder: Arc<OfferLadder>, run: RunAdmission) -> Self {
        Self {
            ladder,
            run,
            served: std::sync::Mutex::new(None),
        }
    }

    /// The model of the rung that answered last, if one did.
    pub(super) fn served(self) -> Option<ModelId> {
        self.served
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// One generation on `run`, keeping the model that answered.
    fn generate_on<'a>(
        &'a self,
        run: &'a RunAdmission,
        request: LlmRequest,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let generated = self.ladder.generate_served(run, request, None).await;
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
        self.generate_on(&self.run, request)
    }

    fn stream<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.ladder.stream(&self.run, request, None)
    }
}

impl SourcedBackend for ServedRealization {
    fn sourced(&self, rows: Vec<EntityId>) -> Box<dyn LlmBackend + '_> {
        Box::new(SourcedRealization {
            realization: self,
            run: self.run.sourced(Some(rows)),
        })
    }
}

/// One realization call on its run bound to its rows.
struct SourcedRealization<'r> {
    realization: &'r ServedRealization,
    run: RunAdmission,
}

impl LlmBackend for SourcedRealization<'_> {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.realization.supports(model, capability)
    }

    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        self.realization.generate_on(&self.run, request)
    }

    fn stream<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.realization.ladder.stream(&self.run, request, None)
    }
}
