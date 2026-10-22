//! The legs' exact-model calls: each arm on its own one-model ladder, as a
//! call of the seat's role, under one route prompt and the same task, with
//! no fallback. An arm this host does not serve exactly is no leg, and no
//! other model stands in.

use std::collections::BTreeMap;

use oneiron::llm::manifest::ModelRole;
use oneiron::llm::mark_solo;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill_optimize::{
    EvalArmPin, EvalMeasurement, EvalTaskInput, MeasurementUnavailable, seat_model_role,
};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, LlmError, LlmMessage, LlmMessageRole,
    LlmRequest, LlmResponse, ModelId, ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence,
    Vault,
};
use serde_json::Value;

use crate::server::SyncServer;

/// The call purpose a measurement's calls are metered under.
const CALL_PURPOSE: &str = "coach_eval_measurement";

/// One arm as this host serves it exactly.
pub(super) struct ServedArm {
    model: ModelId,
    locality: ModelLocality,
}

/// Both arms, served exactly under one route prompt, and the role they
/// answer as.
pub(super) struct Arms {
    pub(super) incumbent: ServedArm,
    pub(super) candidate: ServedArm,
    role: ModelRole,
    prompt: Option<String>,
}

/// Whether a measurement's arms can run here.
pub(super) enum Opened {
    Ready(Arms),
    /// Not served exactly here now: nothing is counted or paid.
    Unserved,
    /// Never measurable as asked.
    Refused(MeasurementUnavailable),
}

/// One leg's call.
pub(super) enum Generated {
    Answer {
        text: String,
        /// The provider that answered, as the ladder stamped it.
        served: Option<String>,
    },
    Unavailable(MeasurementUnavailable),
}

enum Served {
    Exact(ServedArm, Option<String>),
    Unserved,
    Refused(MeasurementUnavailable),
}

/// Where this host serves `arm` exactly, and the route prompt its one-model
/// ladder puts first.
fn served(server: &SyncServer, vault: &Vault, arm: &EvalArmPin) -> oneiron::Result<Served> {
    let Ok(model) = ModelId::new(arm.model.clone()) else {
        return Ok(Served::Refused(MeasurementUnavailable::NoExactModelRoute));
    };
    // The registry's serving revision must still be the pin: another
    // revision is another arm.
    let revision = vault
        .model_registry_row(&model)?
        .and_then(|row| row.backends().ok()?.into_iter().next())
        .map(|backend| backend.pin.serving_revision);
    if revision.as_deref() != Some(arm.revision.as_str()) {
        return Ok(Served::Refused(MeasurementUnavailable::PinMoved));
    }
    let Some((locality, ladder)) = server
        .ai
        .model_runtime()
        .router()
        .and_then(|router| router.served(&model))
    else {
        return Ok(Served::Unserved);
    };
    let Some(prompt) = ladder.exact_prompt() else {
        return Ok(Served::Unserved);
    };
    Ok(Served::Exact(
        ServedArm { model, locality },
        prompt.map(str::to_owned),
    ))
}

/// The measurement's arms as this host serves them. Both must answer as
/// one picked model under the same route prompt.
pub(super) fn open(
    server: &SyncServer,
    vault: &Vault,
    row: &EvalMeasurement,
) -> oneiron::Result<Opened> {
    let Some(role) = seat_model_role(&row.request.seat) else {
        return Ok(Opened::Refused(MeasurementUnavailable::NoModelRole));
    };
    let incumbent = served(server, vault, &row.request.incumbent)?;
    let candidate = served(server, vault, &row.request.candidate)?;
    Ok(match (incumbent, candidate) {
        (Served::Refused(reason), _) | (_, Served::Refused(reason)) => Opened::Refused(reason),
        (Served::Exact(incumbent, first), Served::Exact(candidate, second)) => {
            if first == second {
                Opened::Ready(Arms {
                    incumbent,
                    candidate,
                    role,
                    prompt: first,
                })
            } else {
                Opened::Refused(MeasurementUnavailable::InstructionDiffers)
            }
        }
        _ => Opened::Unserved,
    })
}

/// The task as every leg is given it: the input's text when it is one
/// string, else its JSON.
pub(super) fn task_text(task: &EvalTaskInput) -> String {
    match &task.input {
        Value::String(text) => text.clone(),
        input => input.to_string(),
    }
}

/// An answer as text, whole.
fn answer_text(response: &LlmResponse) -> String {
    response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

/// The leg's request: the task alone, as one user message, to `arm`'s model.
fn request(arm: &ServedArm, task: &str) -> LlmRequest {
    let purpose = CallPurpose::Other {
        name: CALL_PURPOSE.to_owned(),
    };
    let mut request = LlmRequest {
        model: arm.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef(CALL_PURPOSE.to_owned())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: arm.locality,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: task.to_owned(),
            }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    };
    // The arms are compared with each other: each runs alone on an own
    // server that batches (INF 1).
    mark_solo(&mut request);
    request
}

impl Arms {
    /// One leg on `arm`, paid by the job's run within its clock. A budget
    /// or clock that ran out, a refused admission or a failed call is no
    /// answer, with its reason.
    pub(super) fn generate(
        &self,
        server: &SyncServer,
        vault: &Vault,
        run: &RunAdmission,
        arm: &ServedArm,
        task: &str,
        clock: &RetrievalDeadline,
    ) -> Generated {
        let runtime = server.ai.model_runtime();
        let Ok(call) = runtime.admit_seat_bound(vault, self.role, request(arm, task)) else {
            return Generated::Unavailable(MeasurementUnavailable::NoExactModelRoute);
        };
        if call.ladder.exact_prompt() != Some(self.prompt.as_deref()) {
            return Generated::Unavailable(MeasurementUnavailable::InstructionDiffers);
        }
        let may_send = || !clock.decision_time_left().is_zero();
        if !may_send() {
            return Generated::Unavailable(MeasurementUnavailable::ClockExhausted);
        }
        let answered =
            tokio::runtime::Handle::current().block_on(call.ladder.generate_exact_within(
                run,
                call.request,
                None,
                &may_send,
                clock.decision_time_left(),
            ));
        match answered {
            Ok(response) => Generated::Answer {
                text: answer_text(&response),
                served: response.usage.served_provider().map(str::to_owned),
            },
            Err(LlmError::BudgetDenied(_)) => {
                Generated::Unavailable(MeasurementUnavailable::BudgetExhausted)
            }
            Err(_) if clock.decision_time_left().is_zero() => {
                Generated::Unavailable(MeasurementUnavailable::ClockExhausted)
            }
            Err(error) => {
                tracing::debug!(%error, "an eval measurement leg failed");
                Generated::Unavailable(MeasurementUnavailable::GenerationFailed)
            }
        }
    }
}
