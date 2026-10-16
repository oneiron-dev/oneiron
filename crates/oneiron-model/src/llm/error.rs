//! Error taxonomy: retryable, fatal, and budget-denied errors plus unsupported-capability detail.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{LlmCapability, ModelId};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, thiserror::Error)]
pub enum LlmError {
    #[error("retryable LLM error: {0}")]
    Retryable(#[from] RetryableLlmError),
    #[error("fatal LLM error: {0}")]
    Fatal(#[from] FatalLlmError),
    #[error("LLM budget denied: {0}")]
    BudgetDenied(#[from] BudgetDenied),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
pub enum RetryableLlmError {
    #[error("rate limited")]
    RateLimited {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after: Option<u64>,
    },
    #[error("server error")]
    ServerError,
    #[error("timeout")]
    Timeout,
    #[error("stream cut")]
    StreamCut,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
pub enum FatalLlmError {
    #[error("invalid request")]
    InvalidRequest,
    #[error("authentication failed")]
    Auth,
    #[error("content filtered")]
    ContentFiltered,
    #[error("empty response")]
    EmptyResponse,
    #[error("unsupported capability: {0}")]
    Unsupported(UnsupportedCapability),
    #[error("label read failed: {0}")]
    LabelRead(LabelReadFailure),
}

/// Why a decision read's answer cannot be read as its label probabilities. Each is checked on
/// every call, and a read that fails one is refused, never taken as p = 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
pub enum LabelReadFailure {
    /// The read generated text: it scored nothing.
    #[error("emitted text")]
    EmittedText,
    /// The read did not stop at the forced end of generation.
    #[error("not an end-of-generation stop")]
    NotEosStop,
    /// A label's probability is absent from the read.
    #[error("missing labels")]
    MissingLabels,
    /// The answer is not the read's shape: no single probability row, a value that is not a
    /// finite number, or a body past its bound.
    #[error("malformed")]
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
pub enum BudgetDenied {
    #[error("budget exhausted")]
    Exhausted,
    #[error("lease invalid")]
    LeaseInvalid,
    #[error("admission denied")]
    AdmissionDenied,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnsupportedCapability {
    pub capability: LlmCapability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl fmt::Display for UnsupportedCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.capability)?;
        if let Some(model) = &self.model {
            write!(f, " for {model}")?;
        }
        if let Some(reason) = &self.reason {
            write!(f, ": {reason}")?;
        }
        Ok(())
    }
}
