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

impl LlmError {
    /// Whether this failure says its provider is down, not that the request
    /// or its credentials are wrong: a server error, a timeout, a cut stream
    /// or an empty answer. The offer rests for its health, and a Dreamer
    /// attempt it parks resumes when an offer recovers (OF-305).
    #[must_use]
    pub fn is_provider_unavailable(&self) -> bool {
        matches!(
            self,
            Self::Retryable(
                RetryableLlmError::ServerError
                    | RetryableLlmError::Timeout
                    | RetryableLlmError::StreamCut
            ) | Self::Fatal(FatalLlmError::EmptyResponse)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
pub enum RetryableLlmError {
    /// A spent quota or a rate limit: a 429, or a 403 or 5xx whose body
    /// reads as one ([`super::limit`]).
    #[error("rate limited")]
    RateLimited {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after: Option<u64>,
        /// Each time the refusal says its limit resets, as Unix seconds in
        /// the order it says them. A caller keeps the first one still ahead
        /// on its own clock: a past one is history, not a reset.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        resets_at: Vec<u64>,
    },
    /// A spent usage window or spent prepaid credit (OF-305): the offer is
    /// parked until its window resets, or, for credit, until the owner tops
    /// up or clears it. A rate limit is [`Self::RateLimited`].
    #[error("usage spent")]
    QuotaSpent {
        kind: SpentKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after: Option<u64>,
        /// When the window resets, as Unix seconds; none for credit.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        resets_at: Vec<u64>,
    },
    /// No offer the call may use on this device answered, and the next one
    /// would have taken its work off the device while its world stays here
    /// (world privacy, "Models": no silent fallback to a cloud model).
    /// `resets_at` holds when the first resting offer the call may use is
    /// back, when one rests.
    #[error("kept on device")]
    KeptOnDevice {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after: Option<u64>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        resets_at: Vec<u64>,
    },
    #[error("server error")]
    ServerError,
    #[error("timeout")]
    Timeout,
    #[error("stream cut")]
    StreamCut,
}

/// What a spent limit is: a usage window that resets, or prepaid credit
/// that does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpentKind {
    Window,
    Credit,
}

impl SpentKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Window => "window",
            Self::Credit => "credit",
        }
    }
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
