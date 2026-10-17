//! `POST /v1/llm/decision_read`: the owner's probe of the house model's
//! decision read. It returns the pack read (the question's label
//! probabilities and P(more thinking), the marginals of one joint read, and,
//! when the recipe asks it, P(ask a person), read separately in the same
//! request) and writes nothing, decides nothing and acts on nothing: every
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
use oneiron::BudgetLease;
use oneiron::llm::run_admission::{CallOutcome, RunAdmission};
use oneiron::llm::{
    FatalLlmError, LabelReadFailure, LabelReadRequest, LabelReadout, LabelSet, LlmError, LlmUsage,
    joint_marginals,
};
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
            work_until: None,
        }
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
    // Priced on the prompt it renders; one it cannot render is refused here.
    let reserve = match door.reserve(&request.label_read(&request.questions(&probe))) {
        Ok(reserve) => reserve,
        Err(error) => return failure(error),
    };
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
    // ends nothing the read still holds.
    let read = tokio::task::spawn_blocking(move || {
        let _turn = turn;
        let questions = request.questions(&probe);
        read(&door, &request.label_read(&questions), reserve, run)
    })
    .await;
    match read {
        Ok(Ok(answer)) => Json(answer).into_response(),
        Ok(Err(error)) => failure(error),
        Err(_) => refusal(StatusCode::INTERNAL_SERVER_ERROR, "decision_read_failed"),
    }
}

/// One read under a run of its own on the raw routes' meter: admitted, its
/// permit started just before the call, and settled once after it.
fn read(
    door: &DecisionReadDoor,
    read: &LabelReadRequest<'_>,
    reserve: u64,
    run: RunAdmission,
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
    let answer = answer?;
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
        return Err(malformed());
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

#[cfg(test)]
pub(crate) mod tests;
