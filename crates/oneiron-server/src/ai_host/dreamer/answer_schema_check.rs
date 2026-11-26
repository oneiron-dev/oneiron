//! The host's loan to the Dreamer's nightly answer-schema check (HOUSE-SCHEMA-CHECK): the
//! extraction role's house model on its own-server rung alone, on the pass's own line. The
//! check re-sends the night's captured TURN calls as schema/shadow pairs and judges them,
//! every call to that one rung, never a fallback, also when the seat names a fallback after
//! it. Without such a rung the night skips with its reason. A call bound to the rows its
//! words were read from asks them in the vault before it goes out and at each physical send,
//! and sends nothing once one is erased or withdrawn ([`SourceFence`]), or once a world keeps
//! one of them, or the world the call names, from where the rung's offer sends
//! ([`HouseSources`], REVIEW-10538 round 2).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use oneiron::dreamer_consolidation::SourcedBackend;
use oneiron::dreamer_consolidation::answer_schema::check::{
    AnswerSchemaHouse, run_answer_schema_check,
};
use oneiron::llm::run_admission::RunAdmission;
use oneiron::settings::{ReadDestination, ReleaseHold};
use oneiron::{
    BudgetGuard, BudgetLease, DreamerAdmittedAttempt, DreamerAttemptExecution, EntityId,
    FatalLlmError, LlmBackend, LlmCapability, LlmError, LlmGenerateFuture, LlmRequest,
    LlmStreamResult, ModelId, ModelLocality, Vault, WakeAttemptContext,
};

use super::extraction_egress;
use crate::models::{OfferLadder, SourceAdmission, SourceFence, SourceOffer};
use crate::server::blocking;

/// What one pass lends its answer-schema checks: the ladder and run the extraction route sends
/// on, the vault its sourced calls are fenced in, and the pass's meter.
#[derive(Clone, Copy)]
pub(super) struct CheckLend<'p> {
    pub(super) vault: &'p Arc<Vault>,
    pub(super) ladder: &'p Arc<OfferLadder>,
    pub(super) run: &'p RunAdmission,
    pub(super) guard: &'p BudgetGuard,
    pub(super) egress: bool,
}

impl CheckLend<'_> {
    /// Runs one check on the house rung at exactly its own server: the extraction route's
    /// first own-server rung as a one-rung ladder of its own, under that rung's model, no
    /// fallback, no ceiling filter, no seat admission. With no such rung the night skips
    /// with its reason.
    pub(super) async fn check(
        self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let Some(house_rung) = self.ladder.house_rung_ladder().filter(|house| {
            house
                .ladder
                .for_replay_binding(&house.model, ModelLocality::OwnServer)
                .is_some()
        }) else {
            return run_answer_schema_check(&attempt.status, ctx, None).await;
        };
        let house = house_rung.ladder;
        let model = house_rung.model;
        let backend = ExactHouseBackend {
            prompt: house
                .exact_prompt()
                .flatten()
                .map(|prompt| prompt.to_owned()),
            wait: house.exact_replay_wait(),
            ladder: Arc::clone(&house),
            run: self.run.clone(),
            model: model.clone(),
            vault: Arc::clone(self.vault),
            fence: None,
            rows: Arc::from(Vec::new()),
        };
        let egress = self
            .egress
            .then(|| extraction_egress(BTreeSet::from([model.clone()])));
        run_answer_schema_check(
            &attempt.status,
            ctx,
            Some(AnswerSchemaHouse {
                backend: &backend,
                sourced: Some(&backend),
                guard: self.guard,
                model: model.clone(),
                inference: oneiron::llm::HostInferenceContext {
                    binding: house.host_binding(
                        model.clone(),
                        ModelLocality::OwnServer,
                        house.all_keyless_own_server(),
                    ),
                    extraction_egress: egress.as_deref(),
                },
                destination: house_rung.destination,
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
    /// The same rows, judged for where the rung's offer sends at each physical send
    /// ([`HouseSources`]); empty for a call the engine names no rows for.
    rows: Arc<[EntityId]>,
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
            let sources = HouseSources {
                vault: &self.vault,
                rows: &self.rows,
                world: request.envelope.scope.world,
            };
            replay
                .generate_exact_admitted_within(
                    &self.run,
                    request,
                    self.prompt.as_deref(),
                    &may_send,
                    &sources,
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
        let shared = Arc::from(rows.as_slice());
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
            rows: shared,
        })
    }
}

/// A house call's rows and the world its request names, admitted for where the rung's offer
/// sends (FIX 8714; REVIEW-10538 round 2): before the rung is admitted and again right before
/// each physical send, no world withheld from that destination may keep one of the rows, and
/// the call's world must be one that may go there. A capture kept while its world could go
/// sends nothing once the world is made device-only. Nothing is withheld from a rung on this
/// device; a judge that fails holds the call.
struct HouseSources<'a> {
    vault: &'a Vault,
    rows: &'a [EntityId],
    world: Option<EntityId>,
}

impl HouseSources<'_> {
    fn held(&self, destination: &ReadDestination) -> Option<&'static str> {
        if !destination.is_off_device() {
            return None;
        }
        let verdict = blocking(|| -> oneiron::Result<Option<ReleaseHold>> {
            if !self.vault.rows_may_leave_for(self.rows, destination)? {
                return Ok(Some(ReleaseHold::Placement));
            }
            self.vault.model_call_hold_for(self.world, destination)
        });
        match verdict {
            Ok(hold) => hold.map(ReleaseHold::reason),
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "answer-schema check source admission failed");
                Some(ReleaseHold::Placement.reason())
            }
        }
    }
}

impl SourceAdmission for HouseSources<'_> {
    fn offer(&self, request: &LlmRequest, destination: &ReadDestination) -> SourceOffer {
        match self.held(destination) {
            None => SourceOffer::Send(request.clone()),
            Some(reason) => SourceOffer::Held(reason),
        }
    }

    fn recheck(&self, destination: &ReadDestination) -> Option<&'static str> {
        self.held(destination)
    }
}
