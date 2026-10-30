//! The legs' exact-model calls: each arm on its own one-model ladder, as a
//! call of the seat's role, under one route prompt and the same task, with
//! no fallback. An arm this host does not serve exactly is no leg, and no
//! other model stands in. A skill arm's pinned content is loaded on the
//! job's attempt through the pinned-pack load and goes before the task as
//! the arm's instruction (FIX 10677); content that does not load is no leg.

use std::collections::BTreeMap;

use oneiron::attempt_queue::AttemptRecord;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::mark_solo;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill::{LoadedSkillPack, MeasuredSkillPack};
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
/// A skill package's instruction file.
const SKILL_FILE: &str = "SKILL.md";

/// One arm as this host serves it exactly.
pub(super) struct ServedArm {
    model: ModelId,
    locality: ModelLocality,
    /// A skill arm's pinned content, as the leg reads it.
    skill: Option<String>,
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
        ServedArm {
            model,
            locality,
            skill: None,
        },
        prompt.map(str::to_owned),
    ))
}

/// The skill an arm answers under: its package's SKILL.md, then each other
/// file of it as text under its path, so the leg reads the whole pinned
/// content. `None` when the package holds no readable SKILL.md.
fn skill_text(loaded: &LoadedSkillPack) -> Option<String> {
    let files = loaded.source_files.as_ref()?;
    let mut text = files
        .iter()
        .find(|file| file.path == SKILL_FILE)
        .and_then(|file| std::str::from_utf8(&file.content).ok())?
        .to_owned();
    for file in files.iter().filter(|file| file.path != SKILL_FILE) {
        if let Ok(content) = std::str::from_utf8(&file.content) {
            text.push_str("\n\n--- ");
            text.push_str(&file.path);
            text.push_str(" ---\n");
            text.push_str(content);
        }
    }
    Some(text)
}

/// The content skill arm `digest` pins, loaded on `attempt` through the
/// pinned-pack load; why it is no leg, when it does not load.
fn skill(
    vault: &Vault,
    attempt: &AttemptRecord,
    digest: &str,
    executor: &str,
    now: u64,
) -> oneiron::Result<Result<String, MeasurementUnavailable>> {
    Ok(
        match vault.load_attempt_measured_skill_pack(attempt, digest, executor, now)? {
            MeasuredSkillPack::Loaded(loaded) => {
                skill_text(&loaded).ok_or(MeasurementUnavailable::SkillPackRefused)
            }
            MeasuredSkillPack::Gone => Err(MeasurementUnavailable::SkillContentGone),
            MeasuredSkillPack::Refused => Err(MeasurementUnavailable::SkillPackRefused),
        },
    )
}

/// The measurement's arms as this host serves them. Both must answer as
/// one picked model under the same route prompt; a skill arm also under
/// its pinned content, loaded on the job's `attempt`.
pub(super) fn open(
    server: &SyncServer,
    vault: &Vault,
    row: &EvalMeasurement,
    attempt: &AttemptRecord,
    now: u64,
) -> oneiron::Result<Opened> {
    let Some(role) = seat_model_role(&row.request.seat) else {
        return Ok(Opened::Refused(MeasurementUnavailable::NoModelRole));
    };
    let incumbent = served(server, vault, &row.request.incumbent)?;
    let candidate = served(server, vault, &row.request.candidate)?;
    let (mut incumbent, mut candidate, prompt) = match (incumbent, candidate) {
        (Served::Refused(reason), _) | (_, Served::Refused(reason)) => {
            return Ok(Opened::Refused(reason));
        }
        (Served::Exact(incumbent, first), Served::Exact(candidate, second)) => {
            if first != second {
                return Ok(Opened::Refused(MeasurementUnavailable::InstructionDiffers));
            }
            (incumbent, candidate, first)
        }
        _ => return Ok(Opened::Unserved),
    };
    for (arm, pin) in [
        (&mut incumbent, &row.request.incumbent),
        (&mut candidate, &row.request.candidate),
    ] {
        let Some(digest) = &pin.skill_digest else {
            continue;
        };
        match skill(vault, attempt, digest, &pin.model, now)? {
            Ok(text) => arm.skill = Some(text),
            Err(reason) => return Ok(Opened::Refused(reason)),
        }
    }
    Ok(Opened::Ready(Arms {
        incumbent,
        candidate,
        role,
        prompt,
    }))
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

/// One text message.
fn text_message(role: LlmMessageRole, text: &str) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text {
            text: text.to_owned(),
        }],
    }
}

/// The leg's request to `arm`'s model: a skill arm's pinned content as the
/// instruction, then the task as one user message.
fn request(arm: &ServedArm, task: &str) -> LlmRequest {
    let purpose = CallPurpose::Other {
        name: CALL_PURPOSE.to_owned(),
    };
    let mut messages = Vec::new();
    if let Some(skill) = &arm.skill {
        messages.push(text_message(LlmMessageRole::System, skill));
    }
    messages.push(text_message(LlmMessageRole::User, task));
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
            host_keyless: false,
        },
        messages,
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
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
