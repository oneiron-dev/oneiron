//! One bound Psych Mirror generation step over a profile key's served claims
//! (untangle 6.9i; canon ARCH-0025).
//!
//! A bound profile job cites only served claim versions (RULING
//! S69E2C-PROMPT = A, as the extraction step). The engine renders the
//! psych-mirror skill's body as the instruction and the claims it served,
//! one per line, as the input, and runs them as one durable generation on
//! the attempt's borrowed narrative role. The engine checks the reply
//! (RULING S69I-CAPS-SITE = A): one JSON object of the three tiers, each a
//! non-empty string within its token cap, counted with the context pack's
//! tokenizer, and `compact` shorter than `text`. A tier over its cap is
//! refused whole, never cut. A refused reply answers Failed, is paid and is
//! not memoized, so a resubmit asks again (RULING S69E2D-REPLY-CHECK = A).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::resources::document_version;
use super::roles::{DREAMER_NARRATIVE_ROLE, RoleCall, bind_reasoning};
use crate::dreamer_runner::PsychProfileStepLoan;
use crate::entity_id::EntityId;
use crate::memory::{MemoryError, MemoryResult};
use crate::psych_profile::sources::{ProfileClaim, prompt_lines};
use crate::store::model_step_submission::ModelStepResult;
use crate::tokenizer::DEFAULT_CONTEXT_PACK_TOKENIZER;
use oneiron_model::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, LlmMessage, LlmMessageRole, LlmRequest,
    LlmResponse, ModelTierRef, ResponseFormat, Scope, TierPrecedence,
};

/// The psych-mirror skill as shipped: its body is the step's instruction.
const PSYCH_MIRROR_SKILL: &str = include_str!("../../../../skills/psych-mirror/SKILL.md");

/// The most tokens the `compact` tier may hold.
pub const PSYCH_PROFILE_COMPACT_TOKEN_CAP: usize = 60;
/// The most tokens the `text` tier may hold.
pub const PSYCH_PROFILE_TEXT_TOKEN_CAP: usize = 200;
/// The most tokens the `narrative` tier may hold.
pub const PSYCH_PROFILE_NARRATIVE_TOKEN_CAP: usize = 1200;

/// The three tiers a checked profile reply gives, trimmed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PsychProfileTiers {
    pub compact: String,
    pub text: String,
    pub narrative: String,
}

/// One bound profile step's checked input, snapshotted in validation: the
/// served claims' lines in the job's slot order, the scope of exactly those
/// claim versions, and the claims the call reads.
pub(crate) struct PreparedPsychProfileStep {
    lines: String,
    scope: Scope,
    sources: Vec<EntityId>,
}

/// The step over `claims`, the served claims in the order the job cited
/// them.
pub(crate) fn prepare_psych_profile_step(claims: &[ProfileClaim]) -> PreparedPsychProfileStep {
    PreparedPsychProfileStep {
        lines: prompt_lines(claims),
        scope: Scope {
            readable: claims
                .iter()
                .map(|claim| document_version(claim.claim, &claim.body))
                .collect::<BTreeSet<_>>(),
            ..Scope::default()
        },
        sources: claims.iter().map(|claim| claim.claim).collect(),
    }
}

/// The skill's body: the shipped file without its frontmatter.
fn skill_instruction() -> &'static str {
    PSYCH_MIRROR_SKILL
        .strip_prefix("---")
        .and_then(|rest| rest.split_once("\n---"))
        .map_or(PSYCH_MIRROR_SKILL, |(_, body)| body)
        .trim()
}

/// The tiers `response` gives, or why the step refuses it: one JSON object
/// of exactly the three strings, each non-empty once trimmed and within its
/// token cap, with `compact` holding fewer tokens than `text`.
///
/// # Errors
///
/// The refusal, in words.
pub fn check_psych_profile_reply(
    response: &LlmResponse,
) -> std::result::Result<PsychProfileTiers, String> {
    let reply = super::step_charge::reply_text(response);
    check_psych_profile_text(&reply)
}

/// [`check_psych_profile_reply`] over the reply's text.
///
/// # Errors
///
/// The refusal, in words.
pub fn check_psych_profile_text(reply: &str) -> std::result::Result<PsychProfileTiers, String> {
    let tiers: PsychProfileTiers = serde_json::from_str(reply.trim()).map_err(|error| {
        format!("the profile reply is not its JSON object of three strings: {error}")
    })?;
    let tiers = PsychProfileTiers {
        compact: tiers.compact.trim().to_owned(),
        text: tiers.text.trim().to_owned(),
        narrative: tiers.narrative.trim().to_owned(),
    };
    let mut counts = [0usize; 3];
    for ((name, tier, cap), count) in [
        ("compact", &tiers.compact, PSYCH_PROFILE_COMPACT_TOKEN_CAP),
        ("text", &tiers.text, PSYCH_PROFILE_TEXT_TOKEN_CAP),
        (
            "narrative",
            &tiers.narrative,
            PSYCH_PROFILE_NARRATIVE_TOKEN_CAP,
        ),
    ]
    .into_iter()
    .zip(counts.iter_mut())
    {
        if tier.is_empty() {
            return Err(format!("the profile reply's {name} tier is empty"));
        }
        *count = DEFAULT_CONTEXT_PACK_TOKENIZER.count(tier);
        if *count > cap {
            return Err(format!(
                "the profile reply's {name} tier holds {count} tokens, over its cap of {cap}",
                count = *count
            ));
        }
    }
    if counts[0] >= counts[1] {
        return Err(format!(
            "the profile reply's compact tier ({} tokens) does not compress its text tier ({} tokens)",
            counts[0], counts[1]
        ));
    }
    Ok(tiers)
}

/// The step's request in the skill's words over the prepared lines.
fn psych_profile_request(
    call: &RoleCall<'_>,
    prepared: &PreparedPsychProfileStep,
) -> crate::Result<LlmRequest> {
    let locality = call.inference.selected_locality().ok_or_else(|| {
        crate::Error::InvalidConfig("psych profile host binding needs locality".into())
    })?;
    let text = |role, text: String| LlmMessage {
        role,
        content: vec![ContentPart::Text {
            text,
            signature: None,
        }],
    };
    Ok(LlmRequest {
        model: call.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            // The call reads exactly the claim versions the profile is
            // written from.
            scope: prepared.scope.clone(),
            purpose: CallPurpose::Extraction,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("consolidation".into()),
            ),
            // No schema on the wire, so one submit generates once; the step's
            // check holds the reply to its shape.
            response_format: ResponseFormat::Text,
            locality,
            host_keyless: call.inference.selected_keyless(),
            host_paid: call.inference.selected_paid(),
        }
        .with_purpose_defaults(),
        messages: vec![
            text(LlmMessageRole::System, skill_instruction().to_owned()),
            text(LlmMessageRole::User, prepared.lines.clone()),
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    })
}

fn check_reply(response: &LlmResponse) -> std::result::Result<(), String> {
    check_psych_profile_reply(response).map(drop)
}

/// Runs `prepared` as one durable generation on the borrowed narrative role.
///
/// The request is the skill's body over the prepared lines, authorized for
/// the narrative role, with reasoning bound, sent on the sourced backend
/// bound to the cited claims. The outcome is charged into the shared tally
/// before it moves into the shared request-hash receipt converter. A
/// finished submit, including a memo resubmit, carries the checked tiers as
/// the receipt's JSON.
///
/// # Errors
///
/// The role call's missing locality, the role authorization or reasoning
/// binding refusals, the tally lock or charge failures, and the receipt
/// converter's own failures.
pub(crate) async fn execute_bound_psych_profile_step(
    ctx: &crate::model_step_context::DurableStepContext<'_>,
    prepared: &PreparedPsychProfileStep,
    loan: &PsychProfileStepLoan<'_>,
) -> MemoryResult<crate::llm::model_step::ModelStepReceipt> {
    let request = psych_profile_request(&loan.call, prepared)?;
    let mut request = ctx
        .vault
        .authorize_model_role(DREAMER_NARRATIVE_ROLE, request, &loan.call.inference)?
        .into_request();
    bind_reasoning(ctx.vault, loan.call.backend, &mut request)?;
    let backend = loan.call.call_backend(Some(prepared.sources.clone()));
    let (outcome, unsaved_usage) = crate::llm::call_as_step_checked_with_unsaved_usage(
        ctx,
        backend.get(),
        loan.guard,
        request.clone(),
        &check_reply,
    )
    .await;
    {
        let mut charges = loan.charges.lock().map_err(|_| {
            crate::error::Error::InvariantViolation("psych profile charge tally lock")
        })?;
        super::step_charge::charge_borrowed_slice_outcome(
            ctx.vault,
            &outcome,
            unsaved_usage.as_ref(),
            &mut charges,
        )?;
    }
    let mut receipt =
        crate::llm::request_hash_submit_receipt(ctx.vault, ctx.attempt_id, &request, outcome)?;
    if let Some(ModelStepResult::Finished { response, json, .. }) = receipt.result.as_mut() {
        let tiers = check_psych_profile_reply(response).map_err(MemoryError::bad_request)?;
        *json = Some(
            serde_json::to_value(tiers)
                .map_err(|error| MemoryError::bad_request(error.to_string()))?,
        );
    }
    Ok(receipt)
}
