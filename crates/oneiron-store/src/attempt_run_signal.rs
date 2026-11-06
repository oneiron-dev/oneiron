//! The durable branch signal and ask rows an attempt row carries: each
//! branch-addressed control signal and its settled replay receipt, each
//! needs_input ask with its questions and partial answers, and each masked
//! signal's intent fingerprint. The attempt queue's signal door
//! (`attempt_queue::run_signal`) validates, admits and settles them; the
//! attempt row stores them.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum RunSignalState {
    Pending,
    Settled,
    /// A cancel target ceased being available before its breakpoint.
    RefusedCancelUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum RunAskAnswerKind {
    Word,
    Companion,
    Default,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunAskAnswer {
    pub who: String,
    pub answer: String,
    pub kind: RunAskAnswerKind,
    pub at: u64,
}

/// One question on a durable needs_input handle. The host can display the
/// exact prompt and choices without a live round trip to the worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunAskQuestion {
    pub who: String,
    pub prompt: String,
    pub options: Vec<String>,
    pub deadline: Option<u64>,
}

/// Durable needs_input handle; `answers` may be partial and is readable even
/// after every question was answered. Silence is never treated as consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunAsk {
    pub handle: String,
    pub questions: Vec<RunAskQuestion>,
    pub answers: Vec<RunAskAnswer>,
}

/// One masked signal's intent fingerprint, by the signal's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalIntent {
    pub key: String,
    pub fingerprint: [u8; 32],
}
