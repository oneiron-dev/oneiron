//! A live run's typed decision step (FIX RUN-STEP-TYPED-DECISION-MODE; owner
//! SLICE6-DESIGN S6-1, "a metered, replayable model or decision step";
//! Engine S65-NAMES): `ai.steps.submit` with `live_run` and a `decision` in
//! place of a `request`.
//!
//! The host's decision ladder asks the question through its generated read
//! (ARCH-0076 decide()), and that read's one generation is the run's own
//! model step under the call's key ([`RunStep::submit`]): the run's lease,
//! attachment, definition model list, spend scope and the step's memo and
//! erase custody, as for a model step. The dial's first rung is its ceiling,
//! so nothing past the step's own generation is asked, and a retry of the key
//! replays the saved generation: the same typed answer, with no model call
//! and no spend. The step is admitted as the run's model step is: the run may
//! send the same request as a model step of its own, so the decision step
//! reaches no model and spends no line a model step could not.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use oneiron::llm::decision::catalogue::AI_VERDICT;
use oneiron::llm::decision::{
    AnswerContract, DecisionRung, GeneratedDecisions, GeneratedRung, GeneratedStep, ProviderPin,
    Reversibility, SubmittedRead,
};
use oneiron::llm::model_step::{
    DecisionStepSubmit, ModelStepReceipt, ModelStepResult, ModelStepSubmit, StepSubmitAnswer,
};
use oneiron::llm::{DurableStepError, Scope};
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::{
    BudgetLease, CallClass, CallEnvelope, CallPurpose, EntityId, FatalLlmError, LlmBackend,
    LlmError, LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId, ModelLocality, ModelTierRef,
    ResponseFormat, TierPrecedence,
};
use serde_json::Value;

use super::super::host_doors::support::internal;
use super::RunStep;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The clock the ladder routes one decision step's answer under. The step's
/// generation is bounded by its own declared attempts, its health wait and
/// its provider's timeouts, never by this clock; a week is past anything
/// those add up to, so a reply the step kept is never read as cut, and a
/// retry of the key reads it as the first call did.
const DECISION_STEP_CLOCK: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// [`super::submit_on_run`] for a typed decision step.
pub(super) async fn decide_on_run(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    handle: &str,
    input: DecisionStepSubmit,
) -> MemoryResult<StepSubmitAnswer> {
    let step = RunStep::hold(server, auth, session, handle).await?;
    let runtime = tokio::runtime::Handle::current();
    super::super::clock_ingress::run_blocking(move || step.decide(&runtime, input))
        .await
        .map_err(|_| internal("ai.steps.submit"))?
}

impl RunStep {
    /// The run's typed question through the host's ladder, its one generation
    /// the run's own step `input.step_key`: that step's receipt, and the
    /// typed answer beside it when the step kept a reply. A step that kept none (a
    /// budget trap, a park, a failure) answers its receipt alone, and a
    /// refusal of the step is the call's.
    fn decide(
        self,
        runtime: &tokio::runtime::Handle,
        input: DecisionStepSubmit,
    ) -> MemoryResult<StepSubmitAnswer> {
        let DecisionStepSubmit {
            step_key,
            decision,
            retry,
        } = input;
        if !matches!(
            decision.contract,
            AnswerContract::Noul | AnswerContract::Choice { .. } | AnswerContract::Score { .. }
        ) {
            return Err(MemoryError::bad_request_with(
                "a decision step answers a yes or no, one of its options or a score",
                &["Ask where a target sits in an image through ai.verdict."],
            ));
        }
        // The question `ai.verdict` asks for the same words and contract.
        let key =
            serde_json::to_vec(&decision.contract).map_err(|_| internal("ai.steps.submit"))?;
        let question = AI_VERDICT
            .question(
                &[key.as_slice()],
                decision.question.clone(),
                decision.contract.clone(),
            )
            .map_err(|_| {
                MemoryError::bad_request_with(
                    "the question does not make a typed question",
                    &[
                        "Word it in 1 to 16384 bytes, with at most 64 distinct options of 1 to 256 bytes each, or a score's finite min below its max.",
                    ],
                )
            })?;
        let server = Arc::clone(&self.server);
        let principal = self.actor.entity_ref();
        let host = server.decision_host();
        let mut dial = host.dial(DecisionRung::Big);
        dial.first = DecisionRung::Big;
        dial.ceiling = DecisionRung::Big;
        let policy = host.bands();
        let ladder = host.ladder().ladder();
        let state = decision.state.clone().unwrap_or(Value::Null);
        // The run's step answers inside the read, on this thread; what it
        // answered is kept here, for the call's answer.
        let step = Mutex::new(self);
        let kept: Mutex<Option<MemoryResult<ModelStepReceipt>>> = Mutex::new(None);
        // The read and its rung borrow the kept answer only inside this block.
        let decided = {
            let submit = |request: LlmRequest| -> oneiron::Result<Option<SubmittedRead>> {
                let held = step.lock().unwrap_or_else(PoisonError::into_inner);
                let answered = held.submit(
                    runtime,
                    ModelStepSubmit {
                        step_key: step_key.clone(),
                        request,
                        retry,
                    },
                );
                let read = match &answered {
                    Ok(ModelStepReceipt {
                        result:
                            Some(ModelStepResult::Finished {
                                response, memoized, ..
                            }),
                        ..
                    }) => Some(SubmittedRead {
                        response: response.clone(),
                        memoized: *memoized,
                    }),
                    _ => None,
                };
                *kept.lock().unwrap_or_else(PoisonError::into_inner) = Some(answered);
                Ok(read)
            };
            // The step's own admission is its seal: the request goes out as the
            // run's model step does.
            let seal = |request: LlmRequest| -> oneiron::Result<LlmRequest> { Ok(request) };
            let rung = GeneratedRung {
                pin: ProviderPin {
                    rung: DecisionRung::Big,
                    model: decision.model.as_str().to_owned(),
                    version: decision.model.as_str().to_owned(),
                },
                backend: &StepOnly,
                step: GeneratedStep::Submitted {
                    submit: &submit,
                    vault: server.vault(),
                },
                request: shell(&server, &decision.model),
                seal: &seal,
            };
            // On this thread, outside the runtime: the run's step blocks on it
            // with this call's run-write, idempotency and admission context.
            ladder.run_pack_submitted(
                &rung,
                &[&question],
                principal,
                &[],
                &state,
                dial,
                &policy,
                Reversibility::ReversibleRead,
                &RetrievalDeadline::after(DECISION_STEP_CLOCK),
            )
        };
        // No step was submitted: the ladder refused the question before its
        // read, and its refusal is the call's.
        let Some(submitted) = kept.into_inner().unwrap_or_else(PoisonError::into_inner) else {
            return Err(match decided {
                Err(DurableStepError::Engine(error)) => error.into(),
                Err(error) => MemoryError::bad_request(error.to_string()),
                Ok(_) => internal("ai.steps.submit"),
            });
        };
        // The step's own refusal is the call's.
        let receipt = submitted?;
        // A step that ran answers its receipt, which may be paid for, whatever
        // the ladder read: the typed answer beside it when the ladder read one,
        // none when the step kept no reply (its receipt says why) or its reply
        // did not read as an answer.
        let decision = match decided {
            Ok(GeneratedDecisions::Decided { decisions, .. }) => decisions.into_iter().next(),
            Ok(GeneratedDecisions::Trapped | GeneratedDecisions::Unread(_)) => None,
            Err(error) => {
                tracing::warn!(
                    %error,
                    step_ref = %receipt.step_ref,
                    "a decision step's reply did not read as a typed answer"
                );
                None
            }
        };
        Ok(StepSubmitAnswer { receipt, decision })
    }
}

/// The request a decision step's generation is built on: `model`, an answer
/// generation with no prompt of the host's own; the ladder adds the
/// question's turn and its answer format. Its locality is the one this host
/// serves the model at; a model the host only registers takes its catalog
/// row's at admission.
fn shell(server: &SyncServer, model: &ModelId) -> LlmRequest {
    LlmRequest {
        model: model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Scope::default(),
            purpose: CallPurpose::AnswerGen,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AnswerGen,
                ModelTierRef("default".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: server
                .ai
                .model_locality(model)
                .unwrap_or(ModelLocality::OwnServer),
            host_keyless: false,
            host_paid: false,
        },
        messages: Vec::new(),
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    }
}

/// The generated read's backend slot, which a submitted step never calls:
/// its one generation goes out as the run's own step.
struct StepOnly;

impl LlmBackend for StepOnly {
    fn generate<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        Box::pin(async { Err(LlmError::from(FatalLlmError::InvalidRequest)) })
    }

    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}
