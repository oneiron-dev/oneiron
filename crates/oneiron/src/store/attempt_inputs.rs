//! Queue admission inputs and durable intervention vocabulary.

use serde::{Deserialize, Serialize};

use super::attempt_id::AttemptId;
use super::attempt_result::AttemptResultRef;

/// Durable intervention kind recorded on an attempt row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptInterventionKind {
    Interrupt,
    Pause,
    Resume,
    Cancel,
    Redirect,
}

impl AttemptInterventionKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Cancel => "cancel",
            Self::Redirect => "redirect",
        }
    }
}

/// Durable intervention event appended to an attempt row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptEvent {
    pub sequence: u64,
    pub at: u64,
    pub actor: String,
    pub kind: AttemptInterventionKind,
    #[serde(default)]
    pub note: Option<String>,
}

/// Input for enqueueing an attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnqueueAttempt {
    pub kind: String,
    pub payload: Vec<u8>,
    pub dedupe_key: Option<String>,
    pub run_id: Option<String>,
    pub now: u64,
}

/// Input for atomically claiming the next queued attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimAttempt {
    pub lease_owner: String,
    /// Readiness horizon, capped by the injected clock. Lease timestamps are
    /// recorded from that clock, never from this caller-provided bound.
    pub now: u64,
}

/// Observable effect of an intervention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptInterventionEffect {
    Interrupted,
    Paused,
    AlreadyPaused,
    Resumed,
    AlreadyResumed,
    Cancelled,
    AlreadyCancelled,
    Redirected,
    AlreadyRedirected,
}

impl AttemptInterventionEffect {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupted => "interrupted",
            Self::Paused => "paused",
            Self::AlreadyPaused => "already_paused",
            Self::Resumed => "resumed",
            Self::AlreadyResumed => "already_resumed",
            Self::Cancelled => "cancelled",
            Self::AlreadyCancelled => "already_cancelled",
            Self::Redirected => "redirected",
            Self::AlreadyRedirected => "already_redirected",
        }
    }
}

/// Input for completing a leased attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteAttempt {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub now: u64,
}

/// Input for failing a leased attempt terminally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailAttempt {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub reason: String,
    pub now: u64,
}

/// Input for naming the artifact version a live attempt's result lives in.
///
/// Attaching a result is deliberately its own verb rather than a field on
/// [`CompleteAttempt`]: the exhaust an executor produces is durable BEFORE the
/// row settles, and an executor that then stops without completing must still
/// point at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetAttemptResult {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub result_ref: AttemptResultRef,
    pub now: u64,
}

/// Input for finalizing a leased attempt and scheduling its next try.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryAttempt {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    /// Field spelling is retained for source compatibility; it becomes the new
    /// row's `scheduled_at`.
    pub backoff_until: u64,
    pub last_error: Option<String>,
    pub now: u64,
}
