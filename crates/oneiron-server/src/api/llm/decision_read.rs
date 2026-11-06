//! `POST /v1/llm/decision_read`: the owner's probe of the house model's
//! decision read. It returns the pack read (the question's label
//! probabilities and P(more thinking), the marginals of one joint read, and,
//! when the recipe asks it, P(ask a person), read separately in the same
//! request). It writes only per-call evidence, decides nothing and acts on
//! nothing: every typed decision still goes through decide() in process. The
//! model, endpoint, recipe and paired and person questions are the host's
//! configuration; the caller brings only its question, options and state.
use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use oneiron::code_run::model_call::{
    MODEL_CALL_SCHEMA, ModelCallInputPart, ModelCallKind, ModelCallRecord, NativeReadDigests,
    NativeReadFailure, NativeReadOutcome, native_read_digests, record_model_call_in_txn,
};
use oneiron::code_run::{CapsuleRungBinding, ReadWorldUnknown};
use oneiron::llm::run_admission::{CallOutcome, RunAdmission};
use oneiron::llm::{
    FatalLlmError, LabelReadFailure, LabelReadRequest, LabelReadout, LabelSet, LlmError, LlmUsage,
    ModelId, RetryableLlmError, joint_marginals,
};
use oneiron::{BudgetLease, EntityId, ModelLocality, Vault};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::{failure, refusal};
use crate::auth::CoreAuth;
use crate::config::models::ProbeQuestions;
use crate::models::{DecisionReadDoor, undeclared_run};
use crate::server::SyncServer;

/// The run every probe read is admitted under, one run per read.
const DECISION_READ_RUN: &str = "decision-read";
/// The state bound decide()'s escalation read holds a host to.
const MAX_STATE_BYTES: usize = 65_536;
const MAX_QUESTION_BYTES: usize = 4_096;
/// A choice question's most options, as the decision contract bounds them.
const MAX_OPTIONS: usize = 64;
/// The most one probe read waits, including its worker-acquisition wait:
/// the owner probe brings no deadline, so without this a worker stuck in
/// qualification or crash backoff holds the read (with its turn and its
/// permit) past every provider HTTP timeout (REVIEW-4458 P1).
const PROBE_READ_CUTOFF: std::time::Duration = std::time::Duration::from_secs(300);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReadRequest {
    question: String,
    /// The closed options, in order; absent for a yes/no question.
    #[serde(default)]
    options: Option<Vec<String>>,
    /// Bounded state the caller built; never read from the vault.
    state: JsonValue,
}

#[derive(Serialize)]
struct ReadAnswer {
    model: String,
    revision: String,
    /// The options' probabilities in order; yes, then no, for a yes/no question.
    primary: Vec<f64>,
    paired_yes: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    person_yes: Option<f64>,
    usage: LlmUsage,
}

impl ReadRequest {
    fn valid(&self) -> bool {
        let state_bytes = serde_json::to_vec(&self.state).map_or(usize::MAX, |bytes| bytes.len());
        let options_valid = self.options.as_ref().is_none_or(|options| {
            (2..=MAX_OPTIONS).contains(&options.len())
                && options.iter().enumerate().all(|(index, option)| {
                    !option.trim().is_empty() && !options[..index].contains(option)
                })
        });
        !self.question.trim().is_empty()
            && self.question.len() <= MAX_QUESTION_BYTES
            && options_valid
            && self.state.is_object()
            && state_bytes <= MAX_STATE_BYTES
    }

    /// The pack this request asks: its question jointly with the host's
    /// paired question, then, when set, its person question alone.
    fn questions<'a>(&'a self, probe: &'a ProbeQuestions) -> Vec<LabelReadout<'a>> {
        let mut questions = vec![LabelReadout {
            text: &self.question,
            labels: match &self.options {
                Some(options) => LabelSet::Choice(options),
                None => LabelSet::Noul,
            },
            paired: Some(&probe.paired),
        }];
        if let Some(person) = &probe.person {
            questions.push(LabelReadout {
                text: person,
                labels: LabelSet::Noul,
                paired: None,
            });
        }
        questions
    }

    fn label_read<'a>(&'a self, questions: &'a [LabelReadout<'a>]) -> LabelReadRequest<'a> {
        LabelReadRequest {
            state: &self.state,
            questions,
            work_until: Some(std::time::Instant::now() + PROBE_READ_CUTOFF),
        }
    }
}

pub(super) async fn decision_read(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    Json(request): Json<ReadRequest>,
) -> Response {
    if !auth.is_owner_grade() {
        return refusal(StatusCode::FORBIDDEN, "owner_required");
    }
    // FIX 2222: an owner act; a hosted operator's root is refused, typed.
    let authority = match crate::api::host_action::require_host_owner_act(&server, &auth) {
        Ok(authority) => authority,
        Err(error) => return error.into_response(),
    };
    let Some((door, meter)) = server.decision_read.clone() else {
        return refusal(StatusCode::SERVICE_UNAVAILABLE, "decision_read_unavailable");
    };
    // A reader whose rung `local_reasoner` does not permit is unavailable
    // (FIX 9481), before its state is priced or admitted.
    if !door.permitted() {
        return refusal(StatusCode::SERVICE_UNAVAILABLE, "decision_read_unavailable");
    }
    let Some(probe) = door.probe().cloned() else {
        return refusal(StatusCode::SERVICE_UNAVAILABLE, "decision_read_unavailable");
    };
    if !request.valid() {
        return refusal(StatusCode::BAD_REQUEST, "invalid_request");
    }
    // Priced on the prompt it renders; one it cannot render is refused here.
    let reserve = match door.reserve(&request.label_read(&request.questions(&probe))) {
        Ok(reserve) => reserve,
        Err(error) => return failure(error),
    };
    let principal = match (
        authority
            .as_ref()
            .map(|authority| authority.actor().entity_ref()),
        auth.principal_entity(),
    ) {
        (Some(host), Some(credential)) if host != credential => {
            tracing::warn!("decision-read evidence skipped: conflicting actor bindings");
            None
        }
        (Some(actor), _) | (None, Some(actor)) => Some(actor),
        (None, None) => None,
    };
    let session = super::super::call_receipt::request_session_ref(&headers).map(str::to_owned);
    let no_record_at_arrival = server
        .vault()
        .model_call_keeps_no_record_for(session.as_deref(), principal);
    // Past `limits.decision_reads` a read waits its turn and the row asks; a
    // count never refuses it.
    let Ok(turn) = server.decision_reads.admit(()).await else {
        return refusal(StatusCode::SERVICE_UNAVAILABLE, "decision_read_waited_out");
    };
    let run = undeclared_run(
        DECISION_READ_RUN,
        meter,
        Some(server.host_account()),
        server.run_receipts(),
    );
    // The read blocks on the runtime, so it runs on a blocking thread. Its
    // turn and its permit's settlement go with it: a caller that hangs up
    // ends nothing the read still holds, and no retry is sent past it.
    let caller = CallerPresence::default();
    let present = Arc::clone(&caller.0);
    let read = tokio::task::spawn_blocking(move || {
        let _turn = turn;
        let questions = request.questions(&probe);
        let request = request.label_read(&questions);
        let capture = NativeReadCapture::new(
            server.vault(),
            &request,
            principal,
            session,
            no_record_at_arrival,
        );
        read_retained(&door, &request, reserve, &run, &present, capture.as_ref())
    })
    .await;
    drop(caller);
    match read {
        Ok(Ok(answer)) => Json(answer).into_response(),
        Ok(Err(error)) => failure(error),
        Err(_) => refusal(StatusCode::INTERNAL_SERVER_ERROR, "decision_read_failed"),
    }
}

/// How long a probe its provider refused for rate waits before it goes out
/// again, at least (FIX 8184; CALLS: the requeue floor).
const PROBE_RETRY_FLOOR: std::time::Duration = std::time::Duration::from_secs(1);

/// The most a requeued probe's wait adds at random, so probes refused
/// together come back apart (FIX 8184; CALLS: the jitter range), in
/// milliseconds.
const PROBE_RETRY_JITTER_MS: u64 = 1_000;

/// The probe's caller, while it waits on the read: its handler drops this
/// when the caller hangs up, and the read sends nothing more.
struct CallerPresence(Arc<std::sync::atomic::AtomicBool>);

impl Default for CallerPresence {
    fn default() -> Self {
        Self(Arc::new(std::sync::atomic::AtomicBool::new(true)))
    }
}

impl Drop for CallerPresence {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

/// [`read`], requeued while its provider refuses it for rate (FIX 8184):
/// the probe keeps its fair turn, waits a jittered backoff, and goes out
/// again until its caller hangs up. Each attempt is one permit, dispatched
/// and settled once.
fn read_retained(
    door: &DecisionReadDoor,
    request: &LabelReadRequest<'_>,
    reserve: u64,
    run: &RunAdmission,
    present: &std::sync::atomic::AtomicBool,
    capture: Option<&NativeReadCapture<'_>>,
) -> Result<ReadAnswer, LlmError> {
    use rand_core::RngCore;
    use std::sync::atomic::Ordering;
    let mut call_index = 0_u64;
    loop {
        call_index += 1;
        let answer = read(door, request, reserve, run.clone(), call_index, capture);
        let Err(LlmError::Retryable(RetryableLlmError::RateLimited { retry_after, .. })) = &answer
        else {
            return answer;
        };
        let jitter = rand_core::OsRng.next_u64() % (PROBE_RETRY_JITTER_MS + 1);
        let after = std::time::Duration::from_secs(retry_after.unwrap_or(0));
        let wait = PROBE_RETRY_FLOOR.max(after) + std::time::Duration::from_millis(jitter);
        let until = std::time::Instant::now() + wait;
        while std::time::Instant::now() < until {
            if !present.load(Ordering::Relaxed) {
                return answer;
            }
            let left = until.saturating_duration_since(std::time::Instant::now());
            std::thread::sleep(PROBE_RETRY_SLICE.min(left));
        }
        if !present.load(Ordering::Relaxed) {
            return answer;
        }
    }
}

/// How often a requeued probe's wait looks for its caller.
const PROBE_RETRY_SLICE: std::time::Duration = std::time::Duration::from_millis(100);

/// One attempt under the probe's run on the raw routes' meter: admitted, its
/// permit started just before the call, and settled once after it.
fn read(
    door: &DecisionReadDoor,
    read: &LabelReadRequest<'_>,
    reserve: u64,
    run: RunAdmission,
    call_index: u64,
    capture: Option<&NativeReadCapture<'_>>,
) -> Result<ReadAnswer, LlmError> {
    let permit = run
        .admit_paid(door.connector(), reserve)
        .map_err(LlmError::from)?;
    run.dispatch_paid(permit.lease(), door.connector())
        .map_err(LlmError::from)?;
    let reader = door.reader();
    let lease: &BudgetLease = permit.lease();
    let answer = reader.read(read, lease);
    // The read went out: a failed one keeps its reservation as spend.
    let outcome = match &answer {
        Ok(answer) => CallOutcome::Answered(&answer.usage),
        Err(_) => CallOutcome::Failed,
    };
    if let Err(denied) = permit.settle(outcome) {
        tracing::error!(%denied, "a decision read's settlement was refused");
    }
    let answer = match answer {
        Ok(answer) => answer,
        Err(error) => {
            if let Some(capture) = capture {
                if let Some(failure) = native_read_failure(&error) {
                    capture.record(
                        &run,
                        call_index,
                        reader.model(),
                        reader.revision(),
                        door.connector().locality,
                        NativeReadOutcome::Failed {
                            failure,
                            usage: None,
                        },
                    );
                } else {
                    tracing::warn!("decision-read evidence skipped: unmapped terminal failure");
                }
            }
            return Err(error);
        }
    };
    // The pack is the joint question, then the person question; a readout
    // reports yes first.
    let malformed = || LlmError::from(FatalLlmError::LabelRead(LabelReadFailure::Malformed));
    if answer.readouts.len() != read.questions.len()
        || answer
            .readouts
            .iter()
            .zip(read.questions)
            .any(|(readout, question)| readout.len() != question.width())
    {
        if let Some(capture) = capture {
            capture.record(
                &run,
                call_index,
                reader.model(),
                reader.revision(),
                door.connector().locality,
                NativeReadOutcome::Failed {
                    failure: NativeReadFailure::LabelRead(LabelReadFailure::Malformed),
                    usage: Some(answer.usage.clone()),
                },
            );
        }
        return Err(malformed());
    }
    if let Some(capture) = capture {
        capture.record(
            &run,
            call_index,
            reader.model(),
            reader.revision(),
            door.connector().locality,
            NativeReadOutcome::Completed {
                usage: answer.usage.clone(),
            },
        );
    }
    let (primary, paired_yes) = joint_marginals(&answer.readouts[0]);
    let person_yes = answer
        .readouts
        .get(1)
        .and_then(|readout| readout.first())
        .copied();
    Ok(ReadAnswer {
        model: reader.model().to_owned(),
        revision: reader.revision().to_owned(),
        primary,
        paired_yes,
        person_yes,
        usage: answer.usage,
    })
}

/// A native read has no assistant message or generative request. Its evidence
/// fingerprints the admitted pack and keeps absent usage distinct from zero.
struct NativeReadCapture<'a> {
    vault: &'a Vault,
    actor: EntityId,
    session: Option<String>,
    no_record_at_arrival: bool,
    digests: NativeReadDigests,
}

impl<'a> NativeReadCapture<'a> {
    fn new(
        vault: &'a Vault,
        request: &LabelReadRequest<'_>,
        actor: Option<EntityId>,
        session: Option<String>,
        no_record_at_arrival: bool,
    ) -> Option<Self> {
        let Some(actor) = actor else {
            tracing::debug!("decision-read evidence skipped: actor is unresolved");
            return None;
        };
        let digests = match native_read_digests(request.state, request.questions) {
            Ok(digests) => digests,
            Err(error) => {
                tracing::warn!(%error, "decision-read request digests failed");
                return None;
            }
        };
        Some(Self {
            vault,
            actor,
            session,
            no_record_at_arrival,
            digests,
        })
    }

    fn record(
        &self,
        run: &RunAdmission,
        call_index: u64,
        model: &str,
        revision: &str,
        locality: ModelLocality,
        outcome: NativeReadOutcome,
    ) {
        if self.no_record_at_arrival
            || self
                .vault
                .model_call_keeps_no_record_for(self.session.as_deref(), Some(self.actor))
        {
            return;
        }
        let model = match ModelId::new(model) {
            Ok(model) => model,
            Err(error) => {
                tracing::warn!(%error, "decision-read evidence skipped: invalid reader model id");
                return;
            }
        };
        // Attribution is evidence only, after the provider terminal. The live
        // admission, meter, permit and retry keep their original run.
        let evidence = run.initiated_by(Some(self.actor));
        let record = ModelCallRecord {
            schema: MODEL_CALL_SCHEMA,
            attempt: evidence.instance(),
            lease_generation: u64::from(evidence.revision()),
            call_index,
            kind: ModelCallKind::LabelRead {
                digests: self.digests.clone(),
                revision: revision.to_owned(),
                outcome,
            },
            route: None,
            rung: CapsuleRungBinding {
                model,
                locality,
                prompt: None,
            },
            issuing_login: None,
            organization: None,
            project: None,
            credential_id: None,
            response_id: None,
            thread_id: None,
            previous_response_id: None,
            store: None,
            endpoint: None,
            captured_at: self.vault.now_recorded_at(),
            receipt_ref: None,
            actor: evidence.principal(),
            produced_pending: false,
            tool_rounds: false,
            rounds_truncated: false,
            replay_of: None,
            source_rows: Vec::new(),
            produced_rows: Vec::new(),
            input_parts: vec![ModelCallInputPart::Unknown {
                reason: "decision-read request sources were not captured".to_owned(),
            }],
            reasoning: Vec::new(),
            read_world_epoch: None,
            read_worlds: None,
            read_world_unknown: vec![ReadWorldUnknown::Uncaptured],
            tools_present: false,
            summary_requested: false,
            erased: false,
        };
        if let Err(error) = self
            .vault
            .with_write_txn_grouped(|txn| record_model_call_in_txn(self.vault, txn, &record))
        {
            tracing::warn!(%error, "decision-read model-call record failed");
        }
    }
}

fn native_read_failure(error: &LlmError) -> Option<NativeReadFailure> {
    match error {
        LlmError::Fatal(FatalLlmError::InvalidRequest) => Some(NativeReadFailure::InvalidRequest),
        LlmError::Fatal(FatalLlmError::Auth) => Some(NativeReadFailure::Auth),
        LlmError::Fatal(FatalLlmError::LabelRead(failure)) => {
            Some(NativeReadFailure::LabelRead(*failure))
        }
        LlmError::Retryable(RetryableLlmError::RateLimited { .. }) => {
            Some(NativeReadFailure::RateLimited)
        }
        LlmError::Retryable(RetryableLlmError::Timeout) => Some(NativeReadFailure::Timeout),
        LlmError::Retryable(RetryableLlmError::ServerError) => Some(NativeReadFailure::ServerError),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests;
