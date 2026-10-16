//! `POST /v1/llm/decision_read`: the owner's probe of the house model's
//! decision read. It returns the raw one-pass read (the question's label
//! probabilities, P(more thinking) and, when the recipe asks it, P(ask a
//! person)) and writes nothing, decides nothing and acts on nothing: every
//! typed decision still goes through decide() in process. The model, its
//! endpoint, the recipe and the paired and person questions are the host's
//! configuration; the caller brings only its question, options and state.
use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use oneiron::llm::run_admission::{CallOutcome, RunReceiptSink};
use oneiron::llm::{LabelReadRequest, LabelReadout, LabelSet, LlmError, LlmUsage};
use oneiron::{BudgetGuard, BudgetLease};
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

    /// What the read may reserve: no tokenizer makes more tokens than the
    /// caller's bytes, plus the one position read.
    fn reserve(&self) -> u64 {
        let options: usize = self.options.iter().flatten().map(String::len).sum();
        let bytes = self.question.len() + options + self.state.to_string().len();
        u64::try_from(bytes).unwrap_or(u64::MAX).saturating_add(1)
    }
}

pub(super) async fn decision_read(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Json(request): Json<ReadRequest>,
) -> Response {
    if !auth.is_owner_grade() {
        return refusal(StatusCode::FORBIDDEN, "owner_required");
    }
    let Some((door, meter)) = server.decision_read.clone() else {
        return refusal(StatusCode::SERVICE_UNAVAILABLE, "decision_read_unavailable");
    };
    let Some(probe) = door.probe().cloned() else {
        return refusal(StatusCode::SERVICE_UNAVAILABLE, "decision_read_unavailable");
    };
    if !request.valid() {
        return refusal(StatusCode::BAD_REQUEST, "invalid_request");
    }
    // Past `limits.decision_reads` a read waits its turn and the row asks; a
    // count never refuses it.
    let Ok(turn) = server.decision_reads.admit(()).await else {
        return refusal(StatusCode::SERVICE_UNAVAILABLE, "decision_read_waited_out");
    };
    let receipts = server.run_receipts();
    // The read blocks on the runtime, so it runs on a blocking thread. Its
    // turn and its permit's settlement go with it: a caller that hangs up
    // ends nothing the read still holds.
    let read = tokio::task::spawn_blocking(move || {
        let _turn = turn;
        read(&door, &probe, &request, meter, receipts)
    })
    .await;
    match read {
        Ok(Ok(answer)) => Json(answer).into_response(),
        Ok(Err(error)) => failure(error),
        Err(_) => refusal(StatusCode::INTERNAL_SERVER_ERROR, "decision_read_failed"),
    }
}

#[cfg(test)]
pub(crate) mod tests;

/// One read under a run of its own on the raw routes' meter: admitted, its
/// permit started just before the call, and settled once after it.
fn read(
    door: &DecisionReadDoor,
    probe: &ProbeQuestions,
    request: &ReadRequest,
    meter: BudgetGuard,
    receipts: Arc<dyn RunReceiptSink>,
) -> Result<ReadAnswer, LlmError> {
    let labels = match &request.options {
        Some(options) => LabelSet::Choice(options),
        None => LabelSet::Noul,
    };
    let read = LabelReadRequest {
        state: &request.state,
        primary: LabelReadout {
            text: &request.question,
            labels,
        },
        paired: &probe.paired,
        person: probe.person.as_deref(),
    };
    let run = undeclared_run(DECISION_READ_RUN, meter, receipts);
    let refused = |_| LlmError::from(oneiron::llm::BudgetDenied::AdmissionDenied);
    let permit = run
        .admit_paid(door.connector(), request.reserve())
        .map_err(refused)?;
    run.dispatch_paid(permit.lease(), door.connector())
        .map_err(refused)?;
    let reader = door.reader();
    let lease: &BudgetLease = permit.lease();
    let answer = reader.read(&read, lease);
    // The read went out: a failed one keeps its reservation as spend.
    let outcome = match &answer {
        Ok(answer) => CallOutcome::Answered(&answer.usage),
        Err(_) => CallOutcome::Failed,
    };
    if let Err(denied) = permit.settle(outcome) {
        tracing::error!(%denied, "a decision read's settlement was refused");
    }
    let answer = answer?;
    Ok(ReadAnswer {
        model: reader.model().to_owned(),
        revision: reader.revision().to_owned(),
        primary: answer.primary,
        paired_yes: answer.paired_yes,
        person_yes: answer.person_yes,
        usage: answer.usage,
    })
}
