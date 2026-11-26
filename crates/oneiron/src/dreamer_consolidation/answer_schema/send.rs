//! One answer-schema check's house calls (HOUSE-SCHEMA-CHECK): each arm and each judge turn
//! as a durable step on the house rung, metered. A finished call answers with the spend so
//! far; a step that did not finish parks with it.

use std::collections::BTreeMap;

use serde_json::Value as JsonValue;

use super::super::DREAMER_EXTRACTION_ROLE;
use super::super::request_sources::CallBackend;
use super::check::AnswerSchemaHouse;
use super::pair::{judge_system_text, judge_user_text};
use super::spend::Spend;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::call_as_step;
use crate::model_step_context::{DurableStepContext, StepOutcome};
use crate::model_step_error::DurableStepError;
use oneiron_model::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, LlmMessage, LlmMessageRole, LlmRequest,
    LlmResponse, ModelTierRef, ResponseFormat, Scope, TierPrecedence,
};

/// One house call's answer with the spend so far, or how the attempt waits for one.
pub(crate) type HouseAnswer =
    std::result::Result<(LlmResponse, Spend), crate::dreamer_wake::DreamerAttemptExecution>;

/// Sends `request` as a durable step of the check on the house rung, bound to the rows the
/// call was read from. A finished call answers with the spend so far; a step that did not
/// finish parks with it.
///
/// # Errors
///
/// An engine error the step hit.
pub(crate) async fn send_house(
    step: &DurableStepContext<'_>,
    house: &AnswerSchemaHouse<'_>,
    sources: &[EntityId],
    request: LlmRequest,
    spend: Spend,
) -> Result<HouseAnswer> {
    let backend = CallBackend::new(house.backend, house.sourced, Some(sources.to_vec()));
    match call_as_step(step, backend.get(), house.guard, request).await {
        Ok(StepOutcome::Finished {
            response,
            memoized,
            binding,
            ..
        }) => {
            let mut spend = spend;
            if !memoized {
                spend.add(&response.usage, binding);
            }
            Ok(Ok((response, spend)))
        }
        Ok(StepOutcome::Trapped { .. }) => Ok(Err(spend.trapped())),
        Err(error) => Ok(Err(spend.parked_on(error)?)),
    }
}

/// The schema arm's answer: like [`send_house`]'s, except that a call the provider refused or
/// failed comes back as [`SchemaArm::Failed`] with the spend so far, so the check still sends
/// the shadow arm. A schema the house server cannot compile, or a grammar filter that fails,
/// answers HTTP 400 or 500 on the schema arm alone; that is the fault the two-fault rule
/// exists for, and parking on it would keep the schema on (REVIEW-10538 P1-5). A budget,
/// window or seat refusal is no answer of the arm, and parks as before.
pub(crate) enum SchemaArm {
    /// The arm answered.
    Answered(LlmResponse, Spend),
    /// The provider refused or failed the arm's call.
    Failed(Spend),
    /// The attempt waits, as [`send_house`] parks.
    Parked(crate::dreamer_wake::DreamerAttemptExecution),
}

/// Sends the schema arm as [`send_house`] does, answering a provider's refusal or failure of
/// the call as [`SchemaArm::Failed`].
///
/// # Errors
///
/// An engine error the step hit.
pub(crate) async fn send_schema_arm(
    step: &DurableStepContext<'_>,
    house: &AnswerSchemaHouse<'_>,
    sources: &[EntityId],
    request: LlmRequest,
    spend: Spend,
) -> Result<SchemaArm> {
    let backend = CallBackend::new(house.backend, house.sourced, Some(sources.to_vec()));
    match call_as_step(step, backend.get(), house.guard, request).await {
        Ok(StepOutcome::Finished {
            response,
            memoized,
            binding,
            ..
        }) => {
            let mut spend = spend;
            if !memoized {
                spend.add(&response.usage, binding);
            }
            Ok(SchemaArm::Answered(response, spend))
        }
        Ok(StepOutcome::Trapped { .. }) => Ok(SchemaArm::Parked(spend.trapped())),
        Err(error) if arm_failure(&error) => {
            let mut spend = spend;
            spend.charge_failed(&error);
            Ok(SchemaArm::Failed(spend))
        }
        Err(error) => Ok(SchemaArm::Parked(spend.parked_on(error)?)),
    }
}

/// Whether `error` is the provider's refusal or failure of the call itself: an LLM error,
/// spent or classified, and no budget, window or seat refusal.
fn arm_failure(error: &DurableStepError) -> bool {
    if crate::dreamer_runner::dreamer_failed_on_refused_step(error, 0, &[]).is_some()
        || crate::dreamer_runner::dreamer_seat_refusal_of_step(error).is_some()
    {
        return false;
    }
    matches!(
        error,
        DurableStepError::Llm(_)
            | DurableStepError::SpentLlm { .. }
            | DurableStepError::ClassifiedLlm { .. }
    )
}

/// The judge's request over the source turn and both candidate lists, admitted on the
/// extraction role: turn words leave the vault as an extraction's do. It names `world`, the
/// world the captured call named, so the world settings judge where the turn's words may go
/// as they judged the call's own (REVIEW-10538 round 2).
///
/// # Errors
///
/// The house route names no locality; the role refuses the call.
pub(crate) fn judge_request(
    vault: &Vault,
    house: &AnswerSchemaHouse<'_>,
    world: Option<EntityId>,
    source: &str,
    list1: &[JsonValue],
    list2: &[JsonValue],
) -> Result<LlmRequest> {
    let request = LlmRequest {
        model: house.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Scope {
                world,
                ..Scope::default()
            },
            purpose: CallPurpose::Extraction,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("consolidation".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: house.inference.selected_locality().ok_or_else(invalid)?,
            host_keyless: house.inference.selected_keyless(),
            host_paid: house.inference.selected_paid(),
        }
        .with_purpose_defaults(),
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: judge_system_text().to_owned(),
                    signature: None,
                }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: judge_user_text(source, list1, list2),
                    signature: None,
                }],
            },
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    };
    Ok(vault
        .authorize_model_role(DREAMER_EXTRACTION_ROLE, request, &house.inference)?
        .into_request())
}

/// A reply's text parts joined.
pub(crate) fn response_text(response: &LlmResponse) -> String {
    response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid answer-schema check input".into())
}
