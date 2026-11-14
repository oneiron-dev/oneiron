//! Moved from `crates/oneiron/src/dreamer_runner/free_time/cycle.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use chrono::Datelike;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::dreamer_runner::free_time::cycle::FreeTimeCycleState;
use serde::Deserialize;
use serde::Serialize;

/// What the agent chose for its own time, in its free time for its human.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreeTimeOwnTimeChoice {
    /// Its own dreaming.
    Reflect,
    /// Rest: no call, no spend, no text. It meets the floor.
    Rest,
}

/// The agent's short note to its human on what it got up to. Only the
/// resident writes it, in its item's own result; never its diary, never a
/// stored response, never the engine's words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreeTimeNote {
    pub author: EntityId,
    /// Vault clock seconds.
    pub at: u64,
    pub text: String,
}
