//! A Dreamer-lane TASK's realization: the one row `tasks.create` queues for
//! a TASK routed to the Dreamer. Its lease took the TASK on the highway at
//! admission. One durable model step answers the TASK's spec and brief with
//! the host's wording, or the catalogue's own (`dreamer.task_realize`); the
//! answer lands as one research NOTE the Dreamer authors, and the row's
//! result names it. Completing the row then reports the TASK Done, under
//! its brief's own judgment.
//!
//! The engine ships the wording, so a Dreamer-lane TASK realizes out of the
//! box; it parks only on a host that lends no Dreamer model.

use super::step_charge::StepChargeTally;
use crate::WriteActor;
use crate::attempt_queue::{AttemptQueue, AttemptResultRef, SetAttemptResult};
use crate::dreamer_runner::{DREAMER_TASK_REALIZE_ATTEMPT_KIND, DreamerAdmittedAttempt};
use crate::dreamer_wake::{
    DREAMER_HARD_CUT_PARK_REASON, DreamerAttemptExecution, WakeAttemptContext,
};
use crate::error::{Error, Result};
use crate::llm::manifest::ModelRole;
use crate::llm::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext,
    DurableStepError, HostInferenceContext, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest,
    ModelId, ModelTierRef, ResponseFormat, StepOutcome, TierPrecedence, call_as_step,
};
use std::collections::BTreeMap;

/// Why a TASK's realization parks on a host that lends no Dreamer model.
pub const TASK_REALIZE_UNLENT_PARK_REASON: &str = "task realization needs a lent Dreamer model";

/// The NOTE kind an answer lands as: vault-readable and durable.
const RESULT_NOTE_KIND: &str = "research";

/// What the host lends a TASK's realization.
pub struct TaskRealizeModel<'a> {
    pub backend: &'a dyn LlmBackend,
    pub guard: &'a BudgetGuard,
    pub model: ModelId,
    pub inference: HostInferenceContext<'a>,
    /// The Dreamer role whose route the step runs on.
    pub role: ModelRole,
    /// The Dreamer, who authors the NOTE.
    pub actor: WriteActor,
    /// The host's wording, else
    /// [`TASK_REALIZE_INSTRUCTION`](crate::llm::decision::catalogue::TASK_REALIZE_INSTRUCTION).
    pub instruction: &'a str,
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("task realization: {reason}"))
}

/// Realizes one TASK: asks the lent model with the instruction, the TASK's
/// spec and its brief, writes the answer as one research NOTE under the
/// Dreamer's stamp, and names that NOTE as the row's result. A replay after
/// the result was attached writes nothing; a TASK cancelled or settled since
/// it was queued is owed nothing.
pub async fn run_task_realize(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    model: TaskRealizeModel<'_>,
) -> Result<DreamerAttemptExecution> {
    let record = &attempt.status.attempt;
    if record.kind != DREAMER_TASK_REALIZE_ATTEMPT_KIND {
        return Err(invalid("not a TASK realization"));
    }
    if record.result_ref.is_some() {
        return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
    }
    let Some((task, brief)) =
        crate::task_verb::highway_runner::runner_task_brief(ctx.vault, record)?
    else {
        return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
    };
    let spec =
        serde_json::to_string_pretty(&crate::msgpack_value_to_json(&attempt.status.payload.input))
            .map_err(|_| invalid("the spec is not JSON"))?;
    let mut text = format!(
        "Task: {}\n\n## Spec\n\n```json\n{spec}\n```\n",
        task.to_hex()
    );
    if let Some(brief) = brief {
        let brief =
            serde_json::to_string_pretty(&brief).map_err(|_| invalid("the brief is not JSON"))?;
        text.push_str(&format!("\n## Brief\n\n```json\n{brief}\n```\n"));
    }
    let locality = model
        .inference
        .selected_locality()
        .ok_or_else(|| invalid("the host binding names no locality"))?;
    let request = LlmRequest {
        model: model.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: crate::llm::Scope::default(),
            // The TASK's spec and brief leave the vault as an extraction's
            // records do, so they pass the same egress gate.
            purpose: CallPurpose::Extraction,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("consolidation".into()),
            ),
            response_format: ResponseFormat::Text,
            locality,
        }
        .with_purpose_defaults(),
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: model.instruction.to_owned(),
                }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text { text }],
            },
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    };
    let mut request = ctx
        .vault
        .authorize_model_role(model.role, request, &model.inference)?
        .into_request();
    super::roles::bind_reasoning(ctx.vault, model.backend, &mut request)?;
    let step_hash = request
        .canonical_hash()
        .map_err(|_| invalid("the request did not hash"))?;
    let step_ctx = DurableStepContext {
        vault: ctx.vault,
        attempt_id: record.id,
        run_id: record.run_id.clone(),
        envelope_actor: model.actor,
        subject: task,
        deadline: Some(ctx.deadline),
        now_ms: ctx.now_ms,
    };
    let mut charges = StepChargeTally::default();
    let response = match call_as_step(&step_ctx, model.backend, model.guard, request).await {
        Ok(StepOutcome::Finished { response, .. }) => {
            charges.record_terminal(ctx.vault, record.id, step_hash, &response.usage)?;
            response
        }
        Ok(StepOutcome::Trapped { .. }) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: "durable step trapped for resume".to_owned(),
            });
        }
        Err(DurableStepError::SpentFinalizeRefused { usage }) => {
            charges.record_usage(&usage);
            return Ok(charges.checkpoint());
        }
        Err(DurableStepError::DeadlineHardCut) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: DREAMER_HARD_CUT_PARK_REASON.to_owned(),
            });
        }
        Err(DurableStepError::FinalizeRefused) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: "wake pass finalize window".to_owned(),
            });
        }
        Err(DurableStepError::Engine(error)) => return Err(error),
        Err(other) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: other.to_string(),
            });
        }
    };
    if ctx.deadline.expired() {
        return Ok(charges.checkpoint());
    }
    let answer: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let answer = answer.trim();
    if answer.is_empty() {
        return Ok(charges.park("the model wrote an empty answer"));
    }
    let note = ctx
        .vault
        .create_note(RESULT_NOTE_KIND, answer, model.actor)
        .map_err(|error| invalid(&format!("result note: {error}")))?;
    AttemptQueue::new(ctx.vault).set_result(SetAttemptResult {
        id: record.id,
        lease_owner: record.lease_owner.clone().unwrap_or_default(),
        attempt_count: record.attempt_count,
        result_ref: AttemptResultRef::new(note.to_hex())?,
        now: ctx.now_ms / 1_000,
    })?;
    Ok(DreamerAttemptExecution::Completed {
        completed_units: charges.units,
    })
}
