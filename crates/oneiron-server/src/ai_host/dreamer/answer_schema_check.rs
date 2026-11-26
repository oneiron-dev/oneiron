//! The host's loan to the Dreamer's nightly answer-schema check (HOUSE-SCHEMA-CHECK): the
//! extraction role's house model on its own-server rung alone, on the pass's own line. The
//! check re-sends the night's captured TURN calls as schema/shadow pairs and judges them,
//! every call to that one rung, never a fallback, also when the seat names a fallback after
//! it. Without such a rung the night skips with its reason. A call bound to the rows its
//! words were read from asks them in the vault before it goes out and at each physical send,
//! and sends nothing once one is erased or withdrawn ([`SourceFence`]).

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
    LlmStreamResult, ModelId, ModelLocality, Vault, WakeAttemptContext,
};

use super::extraction_egress;
use crate::models::{OfferLadder, SourceFence};

/// What one pass lends its answer-schema checks: the extraction role's house model with the
/// ladder and run its route sends on, and the pass's meter.
#[derive(Clone, Copy)]
pub(super) struct CheckLend<'p> {
    pub(super) vault: &'p Arc<Vault>,
    pub(super) model: &'p ModelId,
    pub(super) ladder: &'p Arc<OfferLadder>,
    pub(super) run: &'p RunAdmission,
    pub(super) guard: &'p BudgetGuard,
    pub(super) egress: bool,
}

impl CheckLend<'_> {
    /// Runs one check on the house rung at exactly its own server: the configured house
    /// model's first own-server rung as a one-rung ladder of its own, no fallback, no ceiling
    /// filter, no seat admission. With no such rung the night skips with its reason.
    pub(super) async fn check(
        self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let Some(house) = self.ladder.house_rung_ladder(self.model).filter(|house| {
            house
                .for_replay_binding(self.model, ModelLocality::OwnServer)
                .is_some()
        }) else {
            return run_answer_schema_check(&attempt.status, ctx, None).await;
        };
        let backend = ExactHouseBackend {
            prompt: house
                .exact_prompt()
                .flatten()
                .map(|prompt| prompt.to_owned()),
            wait: house.exact_replay_wait(),
            ladder: Arc::clone(&house),
            run: self.run.clone(),
            model: self.model.clone(),
            vault: Arc::clone(self.vault),
            fence: None,
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
                    binding: house.host_binding(
                        self.model.clone(),
                        ModelLocality::OwnServer,
                        house.all_keyless_own_server(),
                    ),
                    extraction_egress: egress.as_deref(),
                },
            }),
        )
        .await
    }
}

/// The house rung as one backend: its one-rung ladder, resolved per call to that rung at
/// exactly its own server, sending without fallback. A call the engine knows the rows of
/// sends on the run sourced with them, fenced by them (REVIEW-10538 P1-1).
struct ExactHouseBackend {
    ladder: Arc<OfferLadder>,
    run: RunAdmission,
    model: ModelId,
    /// The rung's configured route prompt, which the exact call keeps.
    prompt: Option<String>,
    wait: Duration,
    vault: Arc<Vault>,
    /// The rows a sourced call's words were read from: asked before the call and at each
    /// physical send; `None` for a call the engine names no rows for.
    fence: Option<SourceFence>,
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
            let may_send = || self.fence.as_ref().is_none_or(SourceFence::stands);
            if !may_send() {
                return Err(LlmError::Fatal(FatalLlmError::InvalidRequest));
            }
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
        let fence = SourceFence::new(Arc::clone(&self.vault), rows.clone());
        Box::new(Self {
            ladder: Arc::clone(&self.ladder),
            run: self
                .run
                .sourced(Some(rows))
                .within_text_dispatch_release(fence.release()),
            model: self.model.clone(),
            prompt: self.prompt.clone(),
            wait: self.wait,
            vault: Arc::clone(&self.vault),
            fence: Some(fence),
        })
    }
}
