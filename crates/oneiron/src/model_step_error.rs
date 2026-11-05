//! Durable model-step failure and reply-check contracts.

use crate::error::Error;
use oneiron_model::llm::{DreamerFailureDecision, FallbackError, LlmError, LlmResponse, LlmUsage};

pub type DurableStepResult<T> = std::result::Result<T, DurableStepError>;

/// A caller's own check of a reply, run after the schema's when the request
/// has one. The error is the reason, as a schema miss carries its errors.
pub type ReplyCheck = dyn Fn(&LlmResponse) -> std::result::Result<(), String> + Send + Sync;

/// Typed failure surface of the durable-step layer.
#[derive(Debug, thiserror::Error)]
pub enum DurableStepError {
    #[error("LLM failure after spent corrective attempts: {source}")]
    SpentLlm {
        source: LlmError,
        usage: Box<LlmUsage>,
    },
    #[error("JSON schema validation failed after {attempts} attempts: {errors:?}")]
    SchemaValidation { attempts: u8, errors: Vec<String> },
    /// Terminal provider response(s) failed schema validation after real spend.
    #[error("JSON schema validation failed after {attempts} spent attempts: {errors:?}")]
    SpentSchemaValidation {
        attempts: u8,
        errors: Vec<String>,
        usage: Box<LlmUsage>,
    },
    /// A fresh correction was refused after prior provider responses spent units.
    #[error("durable step correction refused at wake-pass deadline after spent usage")]
    SpentFinalizeRefused { usage: Box<LlmUsage> },
    #[error(transparent)]
    Engine(#[from] Error),
    #[error(transparent)]
    Llm(#[from] LlmError),
    /// The step's sole retry authority has exhausted or refused this call.
    /// The decision records the resident rule without granting a new route.
    #[error("classified LLM failure: {source}")]
    ClassifiedLlm {
        #[source]
        source: LlmError,
        failure_policy: DreamerFailureDecision,
    },
    #[error("durable step canonicalization failed: {0}")]
    Canonical(#[from] serde_json::Error),
    #[error(transparent)]
    Fallback(#[from] FallbackError),
    /// A deterministic-fallback run failed after corrective attempts spent units.
    #[error("deterministic fallback failure after spent corrective attempts: {source}")]
    SpentFallback {
        source: FallbackError,
        usage: Box<LlmUsage>,
    },
    /// NEW steps are refused once the wake pass enters its graceful-wrap
    /// finalize window (ONE-1305); memoized hits still return.
    #[error("durable step refused: wake pass is in its finalize window")]
    FinalizeRefused,
    /// Hard-cut signal still handled by attempt executors. An admitted LLM
    /// call no longer emits it when the wake-pass deadline expires.
    #[error("durable step hard cut at the wake-pass deadline")]
    DeadlineHardCut,
}

impl DurableStepError {
    /// Actual provider usage retained by a failed step, separate from earlier completed steps.
    pub(crate) fn spent_usage(&self) -> Option<&LlmUsage> {
        match self {
            Self::SpentLlm { usage, .. }
            | Self::SpentSchemaValidation { usage, .. }
            | Self::SpentFinalizeRefused { usage }
            | Self::SpentFallback { usage, .. } => Some(usage.as_ref()),
            _ => None,
        }
    }
}
