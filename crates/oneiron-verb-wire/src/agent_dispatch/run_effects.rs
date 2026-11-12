//! Moved from `crates/oneiron/src/agent_dispatch/run_effects.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What the owner's answer to a replayed effect's ask came to (FIX 4747
/// slice 7).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentRunEffectAnswerOutcome {
    /// The effect goes once more, at the run's next pass over it.
    ResendReleased,
    /// The effect is not made again: the step reads that it may have
    /// happened elsewhere.
    Left,
    /// An earlier answer settled the ask, or no ask waits on that effect:
    /// this answer changed nothing.
    AlreadySettled,
}
