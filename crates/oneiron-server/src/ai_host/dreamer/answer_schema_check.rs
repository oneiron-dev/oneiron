//! The host's loan to the Dreamer's nightly answer-schema check (HOUSE-SCHEMA-CHECK): the
//! extraction role's house model on its own-server rung alone, on the pass's own line. The
//! check re-sends the night's captured TURN calls as schema/shadow pairs and judges them,
//! every call to the one picked rung, never a fallback. Without that exact rung the night
//! skips with its reason.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use oneiron::dreamer_consolidation::SourcedBackend;
use oneiron::dreamer_consolidation::answer_schema::check::{
    AnswerSchemaHouse, run_answer_schema_check,
};
use oneiron::llm::run_admission::RunAdmission;
use oneiron::{
    BudgetGuard, BudgetLease, DreamerAdmittedAttempt, DreamerAttemptExecution, EntityId,
    FatalLlmError, LlmBackend, LlmCapability, LlmError, LlmGenerateFuture, LlmRequest,
    LlmStreamResult, ModelId, ModelLocality, WakeAttemptContext,
};

use super::extraction_egress;
use crate::models::OfferLadder;

/// What one pass lends its answer-schema checks: the extraction role's house model with the
/// ladder and run its route sends on, and the pass's meter.
#[derive(Clone, Copy)]
pub(super) struct CheckLend<'p> {
    pub(super) model: &'p ModelId,
    pub(super) ladder: &'p Arc<OfferLadder>,
    pub(super) run: &'p RunAdmission,
    pub(super) guard: &'p BudgetGuard,
    pub(super) egress: bool,
}

impl CheckLend<'_> {
    /// Runs one check on the house rung at exactly its own server: the configured house
    /// model's one picked rung, no fallback, no ceiling filter, no seat admission. `None`
    /// for any other ladder, and the night skips with its reason.
    pub(super) async fn check(
        self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        if self
            .ladder
            .for_replay_binding(self.model, ModelLocality::OwnServer)
            .is_none()
        {
            return run_answer_schema_check(&attempt.status, ctx, None).await;
        }
        let backend = ExactHouseBackend {
            ladder: Arc::clone(self.ladder),
            run: self.run.clone(),
            model: self.model.clone(),
            prompt: self
                .ladder
                .exact_prompt()
                .flatten()
                .map(|prompt| prompt.to_owned()),
            wait: self.ladder.exact_replay_wait(),
        };
        let egress = self
            .egress
            .then(|| extraction_egress(BTreeSet::from([self.model.clone()])));
        run_answer_schema_check(
            &attempt.status,
            ctx,
            Some(AnswerSchemaHouse {
                backend: &backend,
                sourced: Some(&backend),
                guard: self.guard,
                model: self.model.clone(),
                inference: oneiron::llm::HostInferenceContext {
                    binding: self.ladder.host_binding(
                        self.model.clone(),
                        ModelLocality::OwnServer,
                        self.ladder.all_keyless_own_server(),
                    ),
                    extraction_egress: egress.as_deref(),
                },
            }),
        )
        .await
    }
}

/// The house rung as one backend: its ladder, resolved per call to the house model's one
/// picked rung at exactly its own server, sending without fallback. A call the engine
/// knows the rows of sends on the run sourced with them.
struct ExactHouseBackend {
    ladder: Arc<OfferLadder>,
    run: RunAdmission,
    model: ModelId,
    /// The rung's configured route prompt, which the exact call keeps.
    prompt: Option<String>,
    wait: Duration,
}

impl LlmBackend for ExactHouseBackend {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.ladder.supports(model, &capability)
    }

    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let replay = self
                .ladder
                .for_replay_binding(&self.model, ModelLocality::OwnServer)
                .ok_or(LlmError::Fatal(FatalLlmError::InvalidRequest))?;
            let may_send = || true;
            replay
                .generate_exact_within(
                    &self.run,
                    request,
                    None,
                    self.prompt.as_deref(),
                    &may_send,
                    self.wait,
                )
                .await
        })
    }

    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(LlmError::Fatal(FatalLlmError::InvalidRequest))
    }
}

impl SourcedBackend for ExactHouseBackend {
    fn sourced(&self, rows: Vec<EntityId>) -> Box<dyn LlmBackend + '_> {
        Box::new(Self {
            ladder: Arc::clone(&self.ladder),
            run: self.run.sourced(Some(rows)),
            model: self.model.clone(),
            prompt: self.prompt.clone(),
            wait: self.wait,
        })
    }
}
