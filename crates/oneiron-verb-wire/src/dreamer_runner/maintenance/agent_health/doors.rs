//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/agent_health/doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_runner::maintenance::agent_health::vocabulary::AgentHealthOutcome;
use serde::Deserialize;
use serde::Serialize;

/// The outcome a card's reader sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConcernOutcome {
    Confirmed,
    Dismissed,
    Unresolved,
}

impl From<ConcernOutcome> for AgentHealthOutcome {
    fn from(outcome: ConcernOutcome) -> Self {
        match outcome {
            ConcernOutcome::Confirmed => Self::Confirmed,
            ConcernOutcome::Dismissed => Self::Dismissed,
            ConcernOutcome::Unresolved => Self::Unresolved,
        }
    }
}

/// `self.inbox.concern`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConcernCardRequest {
    /// The card's `health:` handle: the concern row's `payload_ref`.
    pub card: String,
}

/// `self.inbox.concern.outcome`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConcernOutcomeRequest {
    /// The card's `health:` handle: the concern row's `payload_ref`.
    pub card: String,
    pub outcome: ConcernOutcome,
}
