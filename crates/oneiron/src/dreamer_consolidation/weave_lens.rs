//! The weave lens's generate step (OF-499, ARCH-0063 §6): one saved digest
//! period rendered through the shipped `weave-report` skill on the model the
//! host lends. The skill's SKILL.md is the instruction, loaded through the
//! attempt's own skill-load door, so the load is stamped on the attempt. The
//! period's admitted items go in under their keys; the answer is a plan that
//! cites those keys only (`claim::WeaveLensPlan`). A plan that drops, adds
//! or repeats an item is refused, and goes back to the model with why for a
//! repair turn. The plan lands on the period's row, and opening the digest
//! composes it into the reader's lens. A plan still refused after its repair
//! lands as the period's refusal, which the opened digest names.

use super::request_sources::{CallBackend, SourcedBackend};
use super::residency::spent_or_deferred;
use super::step_charge::StepChargeTally;
use crate::attempt_queue::{AttemptQueue, ReadSetProducer};
use crate::claim::{
    WEAVE_LENS_PLAN_REPAIRS, WeaveLensRefusal, WeaveLensRender, WeaveLiveLens,
    weave_lens_answer_plan, weave_lens_repair_text,
};
use crate::dreamer_runner::{
    DREAMER_WEAVE_LENS_ATTEMPT_KIND, DreamerAdmittedAttempt, DreamerParkCause,
};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::error::{Error, Result};
use crate::llm::manifest::ModelRole;
use crate::llm::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext,
    DurableStepError, HostInferenceContext, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest,
    LlmResponse, ModelId, ModelLocality, ModelTierRef, ResponseFormat, StepOutcome, TierPrecedence,
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
    /// `backend` bound per call to the rows its input was read from, when
    /// the host lends that (FIX 6998).
    pub sourced: Option<&'a dyn SourcedBackend>,
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("weave lens render: {reason}"))
}

fn owed_nothing() -> Result<DreamerAttemptExecution> {
    Ok(DreamerAttemptExecution::Completed {
        completed_units: 0,
        step_hashes: Vec::new(),
    })
}

/// One generate step of a period render.
enum LensStep {
    Answer(LlmResponse),
    /// The answer missed the plan's schema through the step's own
    /// corrections; it is paid and there is no text to repair.
    Refused(String),
    /// The attempt ends here instead: parked, or checkpointed with spend.
    Exit(DreamerAttemptExecution),
}

/// Runs `request` as a durable step on `backend`, tallying what it spent.
async fn lens_step(
    step_ctx: &DurableStepContext<'_>,
    model: &WeaveLensModel<'_>,
    backend: &dyn LlmBackend,
    request: LlmRequest,
    charges: &mut StepChargeTally,
    ctx: &WakeAttemptContext<'_>,
) -> Result<LensStep> {
    let step_hash = match request.canonical_hash() {
        Ok(step_hash) => step_hash,
        Err(_) => {
            return spent_or_deferred(invalid("the request did not hash"), ctx, charges)
                .map(LensStep::Exit);
        }
    };
    Ok(
        match call_as_step(step_ctx, backend, model.guard, request).await {
            Ok(StepOutcome::Finished {
                response, memoized, ..
            }) => {
                if let Err(error) = charges.record_terminal(
                    step_ctx.vault,
                    step_ctx.attempt_id,
                    step_hash,
                    &response.usage,
                ) {
                    if !memoized {
                        charges.record_usage(&response.usage);
                    }
                    return spent_or_deferred(error, ctx, charges).map(LensStep::Exit);
                }
                LensStep::Answer(response)
            }
            Ok(StepOutcome::Trapped { .. }) => LensStep::Exit(
                charges.park_for("durable step trapped for resume", DreamerParkCause::Signal),
            ),
            Err(DurableStepError::SpentFinalizeRefused { usage }) => {
                charges.record_usage(&usage);
                LensStep::Exit(charges.checkpoint())
            }
            Err(DurableStepError::SpentSchemaValidation { errors, usage, .. }) => {
                charges.record_usage(&usage);
                LensStep::Refused(format!(
                    "weave lens: the answer missed the plan's schema: {}",
                    errors.join("; ")
                ))
            }
            Err(DurableStepError::DeadlineHardCut) => LensStep::Exit(charges.checkpoint()),
            Err(DurableStepError::FinalizeRefused) => LensStep::Exit(
                charges.park_for("wake pass finalize window", DreamerParkCause::Checkpoint),
            ),
            Err(DurableStepError::Engine(error)) => {
                return spent_or_deferred(error, ctx, charges).map(LensStep::Exit);
            }
            Err(other) => LensStep::Exit(
                charges.park_for(&other.to_string(), DreamerParkCause::of_step(&other)),
            ),
        },
    )
}

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

/// The generate step's request: the skill's SKILL.md as the instruction,
/// the keyed items as the input, and the plan's schema as the answer's form.
fn lens_request(
    model: ModelId,
    locality: ModelLocality,
    keyless: bool,
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
            host_keyless: keyless,
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
        host_segments: None,
    })
}

/// A live render's generate step (`vault.weave.lens`), for a host that calls
/// its route itself: the period render's request over `live`, authorized as
/// a call of `role` on `inference` (as raw inference with no role: an
/// agent's own dreaming model), at the reasoning level a Dreamer call
/// carries. `takes_reasoning` says whether the route's model takes
/// reasoning controls.
///
/// # Errors
///
/// The inference policy's refusal; a binding that names no locality.
pub fn live_weave_lens_request(
    vault: &Vault,
    live: &WeaveLiveLens,
    role: Option<ModelRole>,
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
        false,
        live.instruction.clone(),
        live.input.clone(),
    )?;
    // A role's route is admitted as that role; an agent's own model as raw
    // inference, as its dreaming is.
    let authorized = match role {
        Some(role) => vault.authorize_model_role(role, request, inference)?,
        None => vault.authorize_raw_inference(request, inference)?,
    };
    let mut request = authorized.into_request();
    super::roles::bind_reasoning_for(vault, takes_reasoning, &mut request)?;
    Ok(request)
}

/// Renders one period: re-reads it for its reader, loads the skill, asks
/// the lent model, checks the plan against the period's items and lands it
/// on the row. A refused plan gets [`WEAVE_LENS_PLAN_REPAIRS`] repair turns;
/// then its refusal lands on the row instead. A period re-rendered, withheld,
/// already rendered or refused since it was queued is owed nothing, and
/// neither is one whose skill is retired or whose lens pack is not Active.
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
    if stored.rendered_at != rendered_at || stored.lens.is_some() || stored.lens_refused.is_some() {
        return owed_nothing();
    }
    // The render reads the skill's pack and the period's report: both
    // declared before either reads (FIX 7019, 7073).
    super::declare_attempt_reads(
        ctx.vault,
        record.id,
        &[
            ReadSetProducer::SKILL_PACK,
            ReadSetProducer::DREAMER_WEAVE_REPORT,
        ],
    );
    // The skill is the weave lens pack's: a pack not installed Active, or a
    // lens that no longer mounts, renders nothing.
    let Some((lens, skill)) = crate::claim::weave_report_lens(ctx.vault)? else {
        return owed_nothing();
    };
    let loaded = match ctx.vault.render_mounted_lens(&lens, || {
        ctx.vault.load_attempt_skill_pack(
            record.id,
            &skill,
            record.lease_owner.as_deref().unwrap_or_default(),
            record.attempt_count,
            model.model.as_str(),
            ctx.now_ms / 1_000,
        )
    }) {
        Ok(Some(loaded)) => loaded,
        // A retired, unapproved or deleted skill renders nothing.
        Ok(None) | Err(Error::EntityNotFound | Error::InvalidClaimBody(_)) => {
            return owed_nothing();
        }
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
    super::record_attempt_reads(
        ctx.vault,
        record.id,
        ReadSetProducer::DREAMER_WEAVE_REPORT,
        Some(stored.report.value.source_rows()),
    );
    let text = crate::claim::weave_lens_model_input(ctx.vault, &stored)?;
    // The render's every call reads the skill and the period only: it sends
    // under the attempt's read set, once that set is complete (FIX 6998).
    let rows = AttemptQueue::new(ctx.vault)
        .get(record.id)
        .ok()
        .flatten()
        .and_then(|queued| queued.source_rows().map(<[_]>::to_vec));
    let backend = CallBackend::new(model.backend, model.sourced, rows);
    let locality = model
        .inference
        .selected_locality()
        .ok_or_else(|| invalid("the host binding names no locality"))?;
    let keyless = model.inference.selected_keyless();
    let request = lens_request(model.model.clone(), locality, keyless, instruction, text)?;
    let mut request = ctx
        .vault
        .authorize_model_role(model.role, request, &model.inference)?
        .into_request();
    super::roles::bind_reasoning(ctx.vault, model.backend, &mut request)?;
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
    let mut reason = String::new();
    for _ in 0..=WEAVE_LENS_PLAN_REPAIRS {
        let response = match lens_step(
            &step_ctx,
            &model,
            backend.get(),
            request.clone(),
            &mut charges,
            ctx,
        )
        .await?
        {
            LensStep::Answer(response) => response,
            LensStep::Refused(refused) => {
                reason = refused;
                break;
            }
            LensStep::Exit(exit) => return Ok(exit),
        };
        if ctx.deadline.expired() {
            return Ok(charges.checkpoint());
        }
        match weave_lens_answer_plan(&answer_text(&response), &stored.report.value) {
            Ok(plan) => {
                if let Err(error) = ctx.vault.attach_weave_lens(
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
                ) {
                    return spent_or_deferred(error, ctx, &charges);
                }
                return Ok(DreamerAttemptExecution::Completed {
                    completed_units: charges.units,
                    step_hashes: charges.step_hashes.clone(),
                });
            }
            // The refused answer and why go back to the model; the repair
            // is its own durable step, so a resumed attempt replays both.
            Err(refused) => {
                request.messages.push(response.message);
                request.messages.push(LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![ContentPart::Text {
                        text: weave_lens_repair_text(&stored.report.value, &refused),
                    }],
                });
                reason = refused;
            }
        }
    }
    // Still refused: the period keeps its data, and its row names why it
    // has no render.
    tracing::warn!(
        attempt = ?record.id,
        %reason,
        "the weave lens plan did not meet its period; no render"
    );
    if let Err(error) = ctx.vault.refuse_weave_lens(
        reader,
        scheduled_for,
        rendered_at,
        &WeaveLensRefusal {
            reason,
            skill_ref: skill.to_hex(),
            skill_version: loaded.record.version.clone(),
            model: model.model.as_str().to_owned(),
            refused_at: ctx.vault.store.clock.now_recorded_at(),
        },
    ) {
        return spent_or_deferred(error, ctx, &charges);
    }
    Ok(DreamerAttemptExecution::Completed {
        completed_units: charges.units,
        step_hashes: charges.step_hashes.clone(),
    })
}
