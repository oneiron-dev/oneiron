//! The extraction arms' model side: the shipped adapter on the reader's
//! host, recording each call it makes, and the bench's executor for one wake
//! pass, which runs the engine's `ConsolidationExecutor` for each attempt and
//! answers the rest as a host that lends nothing does.

use std::{
    sync::{Mutex, PoisonError},
    time::Instant,
};

use oneiron::dreamer_consolidation::{
    DREAMER_PERSON_ABOUT_ATTEMPT_TYPE, DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE,
};
use oneiron::dreamer_promotion::{DreamerRunContext, PromotionWriterSink};
use oneiron::dreamer_runner::maintenance::digest::{
    DIGEST_ASSESS_FACET, DIGEST_ASSESS_UNLENT_PARK_REASON,
};
use oneiron::dreamer_runner::maintenance::{
    CLAIM_SOURCE_RECHECK_FACET, COMPACTION_CHECK_FACET, claim_source_recheck, compaction_check,
};
use oneiron::dreamer_runner::{
    DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND, DREAMER_RESIDENT_DREAM_ATTEMPT_KIND, DreamerParkCause,
};
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::{
    BudgetGuard, BudgetLease, ConsolidationDecisions, ConsolidationExecutor,
    DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor,
    DreamerClaimAuthoringStrategy, LlmBackend, LlmCapability, LlmGenerateFuture, LlmRequest,
    LlmStreamResult, LlmUsage, ModelId, ModelLocality, Vault, WakeAttemptContext, WriteActor,
};

use super::super::elapsed_us;
use super::LaneTally;

/// One model call the extraction backend made.
#[derive(Debug, Clone)]
pub(super) struct ExtractionCall {
    /// The provider's usage; none for a call that failed.
    pub(super) usage: Option<LlmUsage>,
    pub(super) elapsed_us: u64,
}

/// The shipped adapter on the reader's host, recording each call it makes.
pub(super) struct RecordingBackend {
    inner: Box<dyn LlmBackend>,
    calls: Mutex<Vec<ExtractionCall>>,
}

impl RecordingBackend {
    pub(super) fn new(inner: Box<dyn LlmBackend>) -> Self {
        Self {
            inner,
            calls: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn calls(&self) -> Vec<ExtractionCall> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(super) fn call_count(&self) -> usize {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

impl LlmBackend for RecordingBackend {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.inner.supports(model, capability)
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let started = Instant::now();
            let result = self.inner.generate(request, lease).await;
            let call = ExtractionCall {
                usage: result.as_ref().ok().map(|response| response.usage.clone()),
                elapsed_us: elapsed_us(started),
            };
            self.calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(call);
            result
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.inner.stream(request, lease)
    }
}

/// The bench's executor for one pass: a `ConsolidationExecutor` per attempt
/// over the pinned extraction model, each with its own promotion sink, whose
/// outcome the lane's tally counts. The sink is the public promotion door's
/// (`PromotionWriterSink`, as the testkit's pass uses it), so each attempt's
/// landed, pended and rejected claims can be counted. Unlike the server's
/// owned attempt sink it records no attempt outputs, so the timer Macro
/// lane's nightly fan-in over recorded child outputs has none to read here.
pub(super) struct BenchExecutor<'p> {
    pub(super) vault: &'p Vault,
    pub(super) backend: &'p RecordingBackend,
    pub(super) guard: &'p BudgetGuard,
    pub(super) actor: WriteActor,
    pub(super) model: ModelId,
    pub(super) locality: ModelLocality,
    pub(super) decisions: ConsolidationDecisions,
    pub(super) run_id: String,
    pub(super) tally: &'p mut LaneTally,
}

impl DreamerAttemptExecutor for BenchExecutor<'_> {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        if let Some(answer) = unlent_answer(&attempt.status.payload.attempt_type) {
            self.tally.attempts_unlent += 1;
            return Ok(answer);
        }
        let mut sink = PromotionWriterSink::new(
            self.vault,
            DreamerRunContext {
                run_id: self.run_id.clone(),
                attempt_id: attempt.status.attempt.id,
                agent_actor: self.actor,
                now_ms: ctx.now_ms,
            },
        );
        // The host's egress verdict: an extraction request may leave only
        // for the run's pinned extraction model.
        let pinned = self.model.clone();
        let egress = move |request: &LlmRequest| request.model == pinned;
        let execution = {
            let mut inner = ConsolidationExecutor {
                backend: self.backend,
                guard: self.guard,
                strategy: DreamerClaimAuthoringStrategy::SinglePass,
                actor: self.actor,
                model: self.model.clone(),
                inference: HostInferenceContext {
                    binding: HostInferenceBinding::Advertised {
                        model: self.model.clone(),
                        locality: self.locality,
                        keyless: false,
                    },
                    extraction_egress: Some(&egress),
                },
                roles: Default::default(),
                sink: &mut sink,
                scope: None,
                decisions: self.decisions.clone(),
            };
            DreamerAttemptExecutor::execute(&mut inner, attempt, ctx).await
        };
        self.tally.claims_landed += sink.outcome.landed.len();
        self.tally.claims_pended += sink.outcome.pended.len();
        self.tally.claims_held += sink.outcome.held.len();
        self.tally.claims_rejected += sink.outcome.rejected.len();
        execution
    }
}

/// What a host that lends nothing answers for `attempt_type`, as
/// oneiron-server's Dreamer host does with nothing lent (the testkit pass's
/// rule): a compaction's check, a claim source re-check, an urgent digest's
/// harm question, a PERSON `about` line and a scope summary park; a
/// resident's dream and its free time for its human complete with no units.
/// `None` for every other shape: a consolidation the executor runs.
fn unlent_answer(attempt_type: &str) -> Option<DreamerAttemptExecution> {
    if attempt_type == DREAMER_RESIDENT_DREAM_ATTEMPT_KIND
        || attempt_type == DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND
    {
        Some(DreamerAttemptExecution::Completed {
            completed_units: 0,
            step_bindings: Vec::new(),
        })
    } else if attempt_type == COMPACTION_CHECK_FACET {
        Some(compaction_check::unlent())
    } else if attempt_type == CLAIM_SOURCE_RECHECK_FACET {
        Some(claim_source_recheck::unlent())
    } else if attempt_type == DIGEST_ASSESS_FACET {
        Some(DreamerAttemptExecution::Park {
            reason: DIGEST_ASSESS_UNLENT_PARK_REASON.to_owned(),
            cause: DreamerParkCause::Retry,
        })
    } else if attempt_type == DREAMER_PERSON_ABOUT_ATTEMPT_TYPE
        || attempt_type == DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE
    {
        Some(DreamerAttemptExecution::Park {
            reason: "the action bench host lends no narrative writer".to_owned(),
            cause: DreamerParkCause::Retry,
        })
    } else {
        None
    }
}
