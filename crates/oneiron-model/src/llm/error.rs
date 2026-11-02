//! Error taxonomy: retryable, fatal, and budget-denied errors plus unsupported-capability detail.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::media::MediaCallProgress;
use super::{LlmCapability, ModelId};

#[derive(
    Debug, Clone, PartialEq, Serialize, Deserialize, thiserror::Error, schemars::JsonSchema,
)]
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
                    | RetryableLlmError::TransportFault(_)
            ) | Self::Fatal(FatalLlmError::EmptyResponse)
        )
    }
}

/// A media call that stopped part way (FIX 9517): the error that stopped
/// it, and what the requests that answered before it completed. Projected
/// onto [`LlmError`] it is that error alone, so a caller that settles no
/// call sees the error it always saw; a run that settles the call settles
/// its progress once, never its whole reservation.
#[derive(Debug, Clone, PartialEq)]
pub struct InterruptedMediaCall {
    pub error: LlmError,
    pub progress: MediaCallProgress,
}

impl InterruptedMediaCall {
    /// A call that completed nothing before `error`.
    #[must_use]
    pub fn nothing(error: LlmError) -> Self {
        Self {
            error,
            progress: MediaCallProgress::default(),
        }
    }
}

impl From<InterruptedMediaCall> for LlmError {
    fn from(call: InterruptedMediaCall) -> Self {
        call.error
    }
}

impl From<LlmError> for InterruptedMediaCall {
    fn from(error: LlmError) -> Self {
        Self::nothing(error)
    }
}

impl From<FatalLlmError> for InterruptedMediaCall {
    fn from(error: FatalLlmError) -> Self {
        Self::nothing(error.into())
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    thiserror::Error,
    schemars::JsonSchema,
)]
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
    /// back, when one rests. `reason` says why the world stays, content-free
    /// (FIX 4939): the owner's recipient choice for it, or an integrity hold;
    /// never a world's name or id.
    #[error("kept on device{}", kept_reason(.reason.as_deref()))]
    KeptOnDevice {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after: Option<u64>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        resets_at: Vec<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// No rung the call reached may take it under its world's own order
    /// (FIX 11768): the order names no route the ladder walks.
    /// Content-free; the receipt's `passed_over` names each refused rung.
    /// An unadmitted rung never rests, so no reset attaches.
    #[error("world route not admitted")]
    WorldRouteNotAdmitted,
    #[error("server error")]
    ServerError,
    #[error("timeout")]
    Timeout,
    #[error("stream cut")]
    StreamCut,
    /// A cut whose transport named its cause (FIX 10403): retried, rested
    /// and parked exactly as [`Self::StreamCut`] is; the cause is for the
    /// result row and receipt that carry the error.
    #[error("stream cut ({0})")]
    TransportFault(TransportFault),
}

/// What cut a call on its transport, as the transport typed it.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    thiserror::Error,
    schemars::JsonSchema,
)]
#[error("{}{}: {detail}", .kind.as_str(), fault_stage(.stage.as_deref()))]
pub struct TransportFault {
    pub kind: TransportFaultKind,
    /// Where on its side the transport was when it failed, when it says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    /// The transport's own words for the fault.
    pub detail: String,
}

/// The typed transport faults a cut call carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransportFaultKind {
    /// The call never left this side.
    NotSent,
    /// The I/O failed after the call went out: it may have run.
    IoAfterSend,
    /// The far end refused the call before anything ran.
    Refused,
    /// The far end sent a frame the call cannot take where it came.
    UnexpectedFrame,
    /// The far end ended the call with an error where no error reply fits.
    EndedWithError,
}

impl TransportFaultKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotSent => "not_sent",
            Self::IoAfterSend => "io_after_send",
            Self::Refused => "refused",
            Self::UnexpectedFrame => "unexpected_frame",
            Self::EndedWithError => "ended_with_error",
        }
    }
}

/// The typed cuts a transport builds, one per [`TransportFaultKind`].
impl RetryableLlmError {
    /// The call never left this side: `stage` failed.
    #[must_use]
    pub fn not_sent(stage: &str, detail: impl Into<String>) -> Self {
        Self::fault(TransportFaultKind::NotSent, Some(stage), detail.into())
    }

    /// The I/O failed at `stage` after the call went out: it may have run.
    #[must_use]
    pub fn io_after_send(stage: &str, detail: impl Into<String>) -> Self {
        Self::fault(TransportFaultKind::IoAfterSend, Some(stage), detail.into())
    }

    /// The far end refused the call, with its `code`, before anything ran.
    #[must_use]
    pub fn refused(code: &str, message: &str) -> Self {
        Self::fault(
            TransportFaultKind::Refused,
            None,
            format!("{code}: {message}"),
        )
    }

    /// The far end sent a frame the call cannot take where it came.
    #[must_use]
    pub fn unexpected_frame(detail: impl Into<String>) -> Self {
        Self::fault(TransportFaultKind::UnexpectedFrame, None, detail.into())
    }

    /// The far end ended the call with an error where no error reply fits.
    #[must_use]
    pub fn ended_with_error(detail: impl Into<String>) -> Self {
        Self::fault(TransportFaultKind::EndedWithError, None, detail.into())
    }

    fn fault(kind: TransportFaultKind, stage: Option<&str>, detail: String) -> Self {
        Self::TransportFault(TransportFault {
            kind,
            stage: stage.map(str::to_owned),
            detail,
        })
    }
}

/// A fault's stage as its message carries it, after its kind.
fn fault_stage(stage: Option<&str>) -> String {
    stage.map_or_else(String::new, |stage| format!(" at {stage}"))
}

/// A kept call's reason as its message carries it, after the hold itself.
fn kept_reason(reason: Option<&str>) -> String {
    reason.map_or_else(String::new, |reason| format!(": {reason}"))
}

/// What a spent limit is: a usage window that resets, or prepaid credit
/// that does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
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

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    thiserror::Error,
    schemars::JsonSchema,
)]
pub enum FatalLlmError {
    #[error("invalid request")]
    InvalidRequest,
    /// A request the provider refused, with its message: an HTTP 400's
    /// error text, bounded.
    #[error("invalid request: {message}")]
    InvalidRequestDetail { message: String },
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
    /// An erase of an owner took the answer (KS-2B2, FIX 6296): a poll of
    /// an erased media job reads this. Terminal: never retried, never a
    /// fallback's trigger, never handed to another offer.
    #[error("response erased")]
    ResponseErased,
}

/// Why a decision read's answer cannot be read as its label probabilities. Each is checked on
/// every call, and a read that fails one is refused, never taken as p = 0.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    thiserror::Error,
    schemars::JsonSchema,
)]
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

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    thiserror::Error,
    schemars::JsonSchema,
)]
pub enum BudgetDenied {
    #[error("budget exhausted")]
    Exhausted,
    #[error("lease invalid")]
    LeaseInvalid,
    #[error("admission denied")]
    AdmissionDenied,
    /// The host asked the account owner a question and holds new host-paid
    /// allocations until it is answered (FIX 9924): nothing is spent, and
    /// the work waits for the owner's answer, never for a top-up.
    #[error("held for the account owner's answer")]
    HostCheck,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
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
