//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/agent_health/doors.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::dreamer_runner::maintenance::agent_health::doors::ConcernCardRequest;
pub use oneiron_verb_wire::dreamer_runner::maintenance::agent_health::doors::ConcernOutcome;
pub use oneiron_verb_wire::dreamer_runner::maintenance::agent_health::doors::ConcernOutcomeRequest;
use serde::Deserialize;
use serde::Serialize;

/// The owner's applied prompt continuation of a card's failed attempt
/// (FIX 3694): the approval it ran under and the successor it enqueued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHealthPromptInject {
    /// The approval's id, as 32 hex.
    pub approval: String,
    /// The successor attempt, as 32 hex.
    pub successor: String,
    /// The Coach ask approved, as 32 hex.
    pub ask: String,
    /// The approving owner.
    pub by: EntityId,
    pub at: u64,
    /// The approved prompt is the owner's edit of the Coach's draft.
    pub edited: bool,
}
