//! Moved from `crates/oneiron/src/agent_dispatch/run_effects.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::agent_dispatch::run_effects::AgentRunEffectAnswerOutcome;
use serde::Deserialize;
use serde::Serialize;

/// The owner's answer on one marked effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRunEffectChoice {
    /// The effect goes once more, under the same intent id.
    Resend,
    /// The effect is not made again; the step reads that it may have
    /// happened elsewhere.
    Leave,
}
