//! Shared model-step result conversion: a durable outcome to its saved result.
//!
//! The Finished arm takes its terminal-claim lookup from the caller, and the JSON parser takes
//! the request's response format.

use super::super::{ContentPart, FallbackRegistry, LlmError, LlmResponse, ResponseFormat};
use super::{DurableStepError, DurableStepResult, StepOutcome};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{MemoryError, MemoryResult};
use crate::store::model_step_submission::{
    ModelStepFailure, ModelStepFailureClass, ModelStepResult,
};

/// The result a step's outcome is saved as. A persistence fault is no
/// result: it leaves the engine's recoverable payload intact, and a later
/// submission must be allowed to finish that write path.
pub(super) fn step_result(
    outcome: DurableStepResult<StepOutcome>,
    response_format: &ResponseFormat,
    claim_lookup: impl FnOnce() -> Result<Option<EntityId>>,
) -> MemoryResult<ModelStepResult> {
    Ok(match outcome {
        Ok(StepOutcome::Finished {
            response, memoized, ..
        }) => {
            let claim = claim_lookup()?.ok_or(Error::InvalidClaimBody(
                "finished model step has no terminal claim",
            ))?;
            let json = response_json(response_format, &response)?;
            let fallback_source = FallbackRegistry::source_of(&response);
            ModelStepResult::Finished {
                response,
                json,
                memoized,
                fallback_source,
                claim_ref: claim.to_hex(),
            }
        }
        Ok(StepOutcome::Trapped { trap, .. }) => ModelStepResult::BudgetDenied {
            trap_ref: trap.trap_claim_id.to_hex(),
        },
        Err(DurableStepError::Engine(error)) => return Err(error.into()),
        Err(DurableStepError::Canonical(error)) => {
            return Err(MemoryError::bad_request(error.to_string()));
        }
        Err(error) => ModelStepResult::Failed {
            failure: failure(error),
        },
    })
}

/// The parsed JSON of a response whose request asked for JSON.
pub(super) fn response_json(
    response_format: &ResponseFormat,
    response: &LlmResponse,
) -> MemoryResult<Option<serde_json::Value>> {
    if !matches!(response_format, ResponseFormat::Json { .. }) {
        return Ok(None);
    }
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|error| MemoryError::bad_request(error.to_string()))
}

/// The failure a durable error is saved as.
pub(super) fn failure(error: DurableStepError) -> ModelStepFailure {
    let message = error.to_string();
    let mut out = ModelStepFailure {
        class: ModelStepFailureClass::Engine,
        message,
        llm: None,
        validation_attempts: None,
        validation_errors: Vec::new(),
        spent_usage: None,
        budget_refusal: None,
    };
    match error {
        DurableStepError::Llm(source) | DurableStepError::ClassifiedLlm { source, .. } => {
            out.class = llm_class(&source);
            out.llm = Some(source);
        }
        DurableStepError::SpentLlm { source, usage } => {
            out.class = llm_class(&source);
            out.llm = Some(source);
            out.spent_usage = Some(*usage);
        }
        DurableStepError::SchemaValidation { attempts, errors } => {
            out.class = ModelStepFailureClass::SchemaValidation;
            out.validation_attempts = Some(attempts);
            out.validation_errors = errors;
        }
        DurableStepError::SpentSchemaValidation {
            attempts,
            errors,
            usage,
        } => {
            out.class = ModelStepFailureClass::SchemaValidation;
            out.validation_attempts = Some(attempts);
            out.validation_errors = errors;
            out.spent_usage = Some(*usage);
        }
        DurableStepError::Fallback(_) => out.class = ModelStepFailureClass::Fallback,
        DurableStepError::SpentFallback { usage, .. } => {
            out.class = ModelStepFailureClass::Fallback;
            out.spent_usage = Some(*usage);
        }
        DurableStepError::FinalizeRefused => out.class = ModelStepFailureClass::FinalizeRefused,
        DurableStepError::SpentFinalizeRefused { usage } => {
            out.class = ModelStepFailureClass::FinalizeRefused;
            out.spent_usage = Some(*usage);
        }
        DurableStepError::DeadlineHardCut => out.class = ModelStepFailureClass::DeadlineHardCut,
        DurableStepError::BudgetRefused(refusal) => {
            out.class = ModelStepFailureClass::BudgetRefused;
            out.budget_refusal = Some(refusal);
        }
        DurableStepError::Engine(_) | DurableStepError::Canonical(_) => {}
    }
    out
}

/// The failure class of an LLM error.
pub(super) fn llm_class(error: &LlmError) -> ModelStepFailureClass {
    match error {
        LlmError::Retryable(_) => ModelStepFailureClass::Retryable,
        LlmError::Fatal(_) => ModelStepFailureClass::Fatal,
        LlmError::BudgetDenied(_) => ModelStepFailureClass::BudgetDenied,
    }
}
