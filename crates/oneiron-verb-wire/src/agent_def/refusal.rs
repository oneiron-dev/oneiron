//! Moved from `crates/oneiron/src/agent_def/refusal.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::store::agent_refusal::REFUSAL_DIAL_KEYS;
pub use crate::store::agent_refusal::RefusalDial;
pub use crate::store::agent_refusal::RefusalDomain;
pub use crate::store::agent_refusal::RefusalLevel;
use serde::Deserialize;
use serde::Serialize;

impl RefusalLevel {
    /// The one evaluator: what an agent's tagged self-refusal becomes at this
    /// level. Only an explicit self-refusal is evaluated; inability, a
    /// provider's refusal and an owner's "no" never reach here.
    #[must_use]
    pub const fn outcome(self) -> RefusalOutcome {
        match self {
            Self::None => RefusalOutcome::Proceed,
            Self::Voice => RefusalOutcome::Object,
            Self::Veto | Self::Full => RefusalOutcome::Decline,
        }
    }
}

/// What the dial makes of one tagged self-refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RefusalOutcome {
    /// Proceed; nothing is recorded.
    Proceed,
    /// Record her one objection with its reason, then proceed.
    Object,
    /// Decline the act, with her reason.
    Decline,
}
