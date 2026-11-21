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

/// The judge's request over the source turn and both candidate lists, admitted on the
/// extraction role: turn words leave the vault as an extraction's do.
///
/// # Errors
///
/// The house route names no locality; the role refuses the call.
pub(crate) fn judge_request(
    vault: &Vault,
    house: &AnswerSchemaHouse<'_>,
    source: &str,
    list1: &[JsonValue],
    list2: &[JsonValue],
) -> Result<LlmRequest> {
    let request = LlmRequest {
        model: house.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Scope::default(),
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
