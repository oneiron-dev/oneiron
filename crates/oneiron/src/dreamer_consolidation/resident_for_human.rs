//! An agent's free time for its human (FIX 4453, `autonomy.for_human`). The
//! resident, under its own stamp and on the model its host lends it, thinks
//! how it could help its human from what it did since its cycle's period
//! began. What it suggests lands as a Proposed claim of its own and is never
//! applied; it may leave its human a short note and choose its own time,
//! its dreaming or rest. The host's instruction stays the voice; the engine
//! adds only the reply's shape ([`FOR_HUMAN_ASK`]).

use std::collections::BTreeMap;

use super::resident_dream::{RESIDENT_DREAM_WINDOW_DEFAULT_TOKENS, ResidentDreamModel};
use super::step_charge::StepChargeTally;
use crate::dreamer_runner::{
    DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND, DreamerAdmittedAttempt, DreamerParkCause,
    FreeTimeForHumanReply, FreeTimeItemRun,
};
use crate::dreamer_wake::{
    DREAMER_HARD_CUT_PARK_REASON, DreamerAttemptExecution, WakeAttemptContext,
};
use crate::error::{Error, Result};
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext, DurableStepError,
    LlmMessage, LlmMessageRole, LlmRequest, ModelTierRef, ResponseFormat, StepOutcome,
    TierPrecedence, call_as_step,
};
use crate::receipt::ReceiptQuery;
use crate::{EntityId, Vault, WriteActor};

/// The share of the window its records may fill; the rest is the reply's.
const INPUT_SHARE_DIVISOR: u64 = 2;
/// The fence that opens the reply's block.
const FOR_HUMAN_FENCE: &str = "```oneiron-free-time";
/// The reply's shape. The host's instruction stays the voice; this says only
/// what the free time is for and where its answer goes.
const FOR_HUMAN_ASK: &str = "This is your free time for your human: think how you could help \
     them. End the reply with one block fenced ```oneiron-free-time holding \
     {\"suggestion\":\"<one thing you suggest for your human>\",\
     \"note\":\"<a short note to your human on what you got up to>\",\
     \"own_time\":\"reflect\"}, where own_time is \"reflect\" or \"rest\" and any field \
     may be null. Your suggestion lands as a proposal your human decides on; nothing is \
     applied. Nothing follows the closing fence.";

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("free time for a resident's human: {reason}"))
}

/// The resident's own receipts since its cycle's period began, oldest
/// first, as many as `room` tokens hold.
fn records_since(vault: &Vault, resident: EntityId, since: u64, room: u64) -> Result<String> {
    let mut receipts = vault.receipts(
        ReceiptQuery::new(usize::MAX)
            .with_actor(resident.to_hex())
            .with_time_bounds((since > 0).then_some(since), None),
    )?;
    receipts.sort_by(|a, b| {
        a.occurred_at
            .cmp(&b.occurred_at)
            .then_with(|| a.receipt_id.cmp(&b.receipt_id))
    });
    let mut left = room;
    let mut text = String::from("## What you did since your last free time\n");
    for receipt in receipts {
        let mut line = format!(
            "- {} {} {}",
            receipt.occurred_at,
            receipt.receipt_kind.as_str(),
            receipt.outcome
        );
        if let Some(job) = &receipt.job_ref {
            line.push_str(&format!(" job {job}"));
        }
        line.push('\n');
        let tokens = crate::count_context_pack_tokens(&line) as u64;
        if tokens > left {
            break;
        }
        left -= tokens;
        text.push_str(&line);
    }
    Ok(text)
}

/// The reply's block, when it holds one that reads.
fn parse_reply(reply: &str) -> Option<FreeTimeForHumanReply> {
    let (_, block) = reply.strip_suffix("```")?.rsplit_once(FOR_HUMAN_FENCE)?;
    serde_json::from_str(block.trim()).ok()
}

/// Runs one resident's free time for its human: reads what it did since its
/// cycle's period began, asks its model with the host's instruction, and
/// lands its suggestion, note and choice under its own stamp. An item whose
/// cycle ended, or that already has its receipt, runs nothing.
pub async fn run_free_time_for_human(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    model: ResidentDreamModel<'_>,
) -> Result<DreamerAttemptExecution> {
    let attempt_id = attempt.status.attempt.id;
    if attempt.status.payload.attempt_type != DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND {
        return Err(invalid("not a free-time attempt for a resident's human"));
    }
    let resident: WriteActor = ctx.vault.resident_actor_for_attempt(attempt_id)?;
    let resident_id = resident.entity_ref();
    let FreeTimeItemRun::Run(binding) =
        crate::dreamer_runner::free_time_item_to_run(ctx.vault, attempt_id, resident_id)?
    else {
        return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
    };
    if !ctx
        .vault
        .get_agent_definition(&resident_id)?
        .is_some_and(|definition| definition.enabled)
    {
        return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
    }
    let window = model
        .window_tokens
        .unwrap_or(RESIDENT_DREAM_WINDOW_DEFAULT_TOKENS);
    let records = records_since(
        ctx.vault,
        resident_id,
        binding.period_start,
        window / INPUT_SHARE_DIVISOR,
    )?;
    let locality = model
        .inference
        .selected_locality()
        .ok_or_else(|| invalid("the host binding names no locality"))?;
    let request = LlmRequest {
        model: model.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: crate::llm::Scope::default(),
            // Its free time for its human. Its own records leave the vault
            // as an extraction's do, so the call is admitted, gated and
            // routed as extraction, and the tier reads that row too.
            purpose: CallPurpose::AutonomyForHuman,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("dreaming".into()),
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
                content: vec![ContentPart::Text {
                    text: format!("{records}\n{FOR_HUMAN_ASK}"),
                }],
            },
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    };
    let authorized = match model.role {
        Some(role) => ctx
            .vault
            .authorize_model_role(role, request, &model.inference)?,
        None => ctx
            .vault
            .authorize_raw_inference(request, &model.inference)?,
    };
    let mut request = authorized.into_request();
    super::roles::bind_reasoning(ctx.vault, model.backend, &mut request)?;
    let step_hash = request
        .canonical_hash()
        .map_err(|_| invalid("the request did not hash"))?;
    let step_ctx = DurableStepContext {
        vault: ctx.vault,
        attempt_id,
        run_id: attempt.status.attempt.run_id.clone(),
        envelope_actor: resident,
        subject: resident_id,
        deadline: Some(ctx.deadline),
        now_ms: ctx.now_ms,
    };
    let mut charges = StepChargeTally::default();
    let response = match call_as_step(&step_ctx, model.backend, model.guard, request).await {
        Ok(StepOutcome::Finished { response, .. }) => {
            charges.record_terminal(ctx.vault, attempt_id, step_hash, &response.usage)?;
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
    let reply: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let parsed = parse_reply(reply.trim());
    crate::dreamer_runner::land_free_time_for_human(ctx.vault, &binding, parsed.as_ref())?;
    Ok(DreamerAttemptExecution::Completed {
        completed_units: charges.units,
    })
}
