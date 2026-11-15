//! Moved from `crates/oneiron/src/engine_executor/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_model::llm::LlmError;

pub const ENGINE_EXECUTOR_SOFT_STEP_LIMIT: u32 = 6;

pub type EngineExecutorResult<T> = std::result::Result<T, EngineExecutorError>;

#[derive(Debug, thiserror::Error)]
pub enum EngineExecutorError {
    #[error(transparent)]
    Engine(#[from] Error),
    #[error(transparent)]
    Llm(#[from] LlmError),
    #[error("executor request canonicalization failed: {0}")]
    CanonicalRequest(#[from] serde_json::Error),
    /// The run's host door refused a call the executor makes for the run,
    /// with the door's stable code.
    #[error("the run's host door refused its call: {code}")]
    HostRefused { code: String },
    /// A resumed pending step's program drifted from its recorded calls, and an effect step
    /// would re-fire: the entry holds with the walk's report (L8-23). The report is the
    /// `oneiron` lib's `ResumePreflightReport`, boxed as an error so this crate need not name
    /// it; a reader takes it back with `downcast_ref`.
    #[error("{0}")]
    ResumeDivergence(Box<dyn std::error::Error + Send + Sync>),
}

impl EngineExecutorError {
    /// The variant, for a log line, which never carries the error's text: an
    /// engine error's can quote what the vault holds, a model error's a reply
    /// or a provider's error body, a canonicalization error's the request.
    pub fn variant(&self) -> &'static str {
        match self {
            Self::Engine(_) => "engine",
            Self::Llm(_) => "llm",
            Self::CanonicalRequest(_) => "canonical_request",
            Self::HostRefused { .. } => "host_refused",
            Self::ResumeDivergence(_) => "resume_divergence",
        }
    }

    /// An engine error's kind, for the same log line.
    pub fn engine_kind(&self) -> Option<oneiron_base::error::ErrorKind> {
        match self {
            Self::Engine(error) => Some(error.kind()),
            _ => None,
        }
    }
}

/// What a fold's `store` names of its inputs: the source the fold read, the
/// reader jobs (children and summaries) it read it by, the summary tree it
/// staged and the recipe it folded by. The host checks each and computes the
/// receipt; the guest never states coverage.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreReceiptInput {
    pub source: String,
    pub tasks: Vec<String>,
    #[serde(default)]
    pub tree: Vec<StoreReceiptTree>,
    #[serde(default)]
    pub recipe: Option<serde_json::Value>,
}

/// One summary of a fold's tree, by ref, and the refs it summarized.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreReceiptTree {
    pub summary: String,
    pub inputs: Vec<String>,
}

/// How a program names one of its run's results. A step's read context
/// keeps the reference each read of another run's result was made by (FIX
/// 6352).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum JsResultRef {
    /// A name the run bound (`r7`).
    Name(String),
    /// A result's handle, as its card gives it or as model context cites it.
    Handle(String),
}
