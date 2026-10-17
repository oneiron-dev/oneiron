//! The weave lens's generate step (OF-499, ARCH-0063 §6): one saved digest
//! period rendered through the shipped `weave-report` skill on the model the
//! host lends. The skill's SKILL.md is the instruction, loaded through the
//! attempt's own skill-load door, so the load is stamped on the attempt. The
//! period's admitted items go in under their keys; the answer is a plan that
//! cites those keys only (`claim::WeaveLensPlan`). A plan that drops, adds
//! or repeats an item is refused. The plan lands on the period's row, and
//! opening the digest composes it into the reader's lens.

use super::step_charge::StepChargeTally;
use crate::claim::{WeaveLensPlan, WeaveLensRender, WeaveLiveLens};
use crate::dreamer_runner::{
    DREAMER_WEAVE_LENS_ATTEMPT_KIND, DreamerAdmittedAttempt, DreamerParkCause,
};
use crate::dreamer_wake::{
    DREAMER_HARD_CUT_PARK_REASON, DreamerAttemptExecution, WakeAttemptContext,
};
use crate::error::{Error, Result};
use crate::llm::manifest::ModelRole;
use crate::llm::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext,
    DurableStepError, HostInferenceContext, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest,
    ModelId, ModelLocality, ModelTierRef, ResponseFormat, StepOutcome, TierPrecedence,
    call_as_step,
};
use crate::{Vault, WriteActor};
use std::collections::BTreeMap;

/// Why a weave lens render parks on a host that lends no Dreamer model.
pub const WEAVE_LENS_UNLENT_PARK_REASON: &str = "a weave lens render needs a lent Dreamer model";

/// The skill file whose body is the instruction.
const SKILL_FILE: &str = "SKILL.md";

/// What the host lends a weave lens render.
pub struct WeaveLensModel<'a> {
    pub backend: &'a dyn LlmBackend,
    pub guard: &'a BudgetGuard,
    pub model: ModelId,
    pub inference: HostInferenceContext<'a>,
    /// The Dreamer role whose route the step runs on.
    pub role: ModelRole,
    /// The Dreamer, whose step it is.
    pub actor: WriteActor,
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("weave lens render: {reason}"))
}

fn owed_nothing() -> Result<DreamerAttemptExecution> {
    Ok(DreamerAttemptExecution::Completed { completed_units: 0 })
}

/// The generate step's request: the skill's SKILL.md as the instruction,
/// the keyed items as the input, and the plan's schema as the answer's form.
fn lens_request(
    model: ModelId,
    locality: ModelLocality,
    instruction: String,
    text: String,
) -> Result<LlmRequest> {
    Ok(LlmRequest {
        model,
        envelope: CallEnvelope {
            seat_effort: None,
            scope: crate::llm::Scope::default(),
            // The items leave the vault as an extraction's records do, so
            // they pass the same egress gate.
            purpose: CallPurpose::Extraction,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("consolidation".into()),
            ),
            response_format: ResponseFormat::Json {
                schema: crate::claim::weave_lens_plan_schema()?,
            },
            locality,
        }
        .with_purpose_defaults(),
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text { text: instruction }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text { text }],
            },
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    })
}

/// A live render's generate step (`vault.weave.lens`), for a host that calls
/// its route itself: the period render's request over `live`, authorized as
/// a call of `role` on `inference`, at the reasoning level a Dreamer call
/// carries. `takes_reasoning` says whether the route's model takes
/// reasoning controls.
///
/// # Errors
///
/// The inference policy's refusal; a binding that names no locality.
pub fn live_weave_lens_request(
    vault: &Vault,
    live: &WeaveLiveLens,
    role: ModelRole,
    model: ModelId,
    inference: &HostInferenceContext<'_>,
    takes_reasoning: bool,
) -> Result<LlmRequest> {
    let locality = inference
        .selected_locality()
        .ok_or_else(|| invalid("the host binding names no locality"))?;
    let request = lens_request(
        model,
        locality,
        live.instruction.clone(),
        live.input.clone(),
    )?;
    let mut request = vault
        .authorize_model_role(role, request, inference)?
        .into_request();
    super::roles::bind_reasoning_for(vault, takes_reasoning, &mut request)?;
    Ok(request)
}

/// Renders one period: re-reads it for its reader, loads the skill, asks
/// the lent model, checks the plan against the period's items and lands it
/// on the row. A period re-rendered, withheld or already rendered since it
/// was queued is owed nothing, and neither is one whose skill is retired.
pub async fn run_weave_lens(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    model: WeaveLensModel<'_>,
) -> Result<DreamerAttemptExecution> {
    let record = &attempt.status.attempt;
    if record.kind != DREAMER_WEAVE_LENS_ATTEMPT_KIND {
        return Err(invalid("not a weave lens render"));
    }
    let (reader, scheduled_for, rendered_at) =
        crate::claim::weave_lens_attempt_period(&attempt.status.payload.input)?;
    let Some(stored) = ctx.vault.weave_digest_for_lens(reader, scheduled_for)? else {
        return owed_nothing();
    };
    if stored.rendered_at != rendered_at || stored.lens.is_some() {
        return owed_nothing();
    }
    let skill = crate::claim::weave_report_skill_id()?;
    let loaded = match ctx.vault.load_attempt_skill_pack(
        record.id,
        &skill,
        record.lease_owner.as_deref().unwrap_or_default(),
        record.attempt_count,
        model.model.as_str(),
        ctx.now_ms / 1_000,
    ) {
        Ok(loaded) => loaded,
        // A retired, unapproved or deleted skill renders nothing.
        Err(Error::EntityNotFound | Error::InvalidClaimBody(_)) => return owed_nothing(),
        Err(error) => return Err(error),
    };
    let Some(instruction) = loaded
        .source_files
        .as_ref()
        .and_then(|files| files.iter().find(|file| file.path == SKILL_FILE))
        .and_then(|file| std::str::from_utf8(&file.content).ok())
        .map(str::to_owned)
    else {
        return owed_nothing();
    };
    let text = crate::claim::weave_lens_model_input(ctx.vault, &stored)?;
    let locality = model
        .inference
        .selected_locality()
        .ok_or_else(|| invalid("the host binding names no locality"))?;
    let request = lens_request(model.model.clone(), locality, instruction, text)?;
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
        subject: reader.id(),
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
                cause: DreamerParkCause::Signal,
            });
        }
        Err(DurableStepError::SpentFinalizeRefused { usage }) => {
            charges.record_usage(&usage);
            return Ok(charges.checkpoint());
        }
        Err(DurableStepError::DeadlineHardCut) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: DREAMER_HARD_CUT_PARK_REASON.to_owned(),
                cause: DreamerParkCause::Checkpoint,
            });
        }
        Err(DurableStepError::FinalizeRefused) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: "wake pass finalize window".to_owned(),
                cause: DreamerParkCause::Checkpoint,
            });
        }
        Err(DurableStepError::Engine(error)) => return Err(error),
        Err(other) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: other.to_string(),
                cause: DreamerParkCause::of_step(&other),
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
    // A plan that does not parse, or does not cite every item exactly once,
    // is refused: the period keeps its data and no render.
    let plan = match serde_json::from_str::<WeaveLensPlan>(answer.trim()) {
        Ok(plan) if plan.validate(&stored.report.value).is_ok() => plan,
        _ => {
            tracing::warn!(
                attempt = ?record.id,
                "the weave lens plan did not meet its period; no render"
            );
            return Ok(DreamerAttemptExecution::Completed {
                completed_units: charges.units,
            });
        }
    };
    ctx.vault.attach_weave_lens(
        reader,
        scheduled_for,
        rendered_at,
        &WeaveLensRender {
            plan,
            skill_ref: skill.to_hex(),
            skill_version: loaded.record.version.clone(),
            model: model.model.as_str().to_owned(),
            rendered_at: ctx.vault.store.clock.now_recorded_at(),
        },
    )?;
    Ok(DreamerAttemptExecution::Completed {
        completed_units: charges.units,
    })
}
