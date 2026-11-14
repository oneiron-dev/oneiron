//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/agent_health/apply.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `/v1/owner/inbox/concern/apply`'s input: the one edit the owner approves.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConcernApplyRequest {
    /// The card's `health:` handle, the row's `payload_ref`.
    pub card: String,
    /// The Coach ask the owner read: its `attempt`, as 32 hex.
    pub ask: String,
    /// The skill revision the edit replaces, as 32 hex.
    pub skill: String,
    /// That revision's version, as the owner read it.
    pub version: String,
    /// The whole replacement instructions the owner approved.
    pub instructions: String,
}

/// Where an approved edit stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealthApplicationState {
    /// The candidate waits on the gate: not yet ruled, deferred, or short of
    /// evidence. Applying again carries it on.
    Pending,
    /// The gate accepted it: the candidate is the skill's active revision.
    Admitted,
    /// The gate rejected or refused it; the skill is as it was.
    Rejected,
}

/// The owner's approval of one ask's skill edit, and where the gate took it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthCoachApplication {
    /// The owner who approved it.
    pub by: EntityId,
    pub at: u64,
    /// The skill revision it replaces, at the version the owner read.
    pub skill: EntityId,
    pub version: String,
    /// The approved instructions' blake3, as hex: applying the same bytes
    /// again is the same application.
    pub instructions: String,
    /// The gated candidate the edit landed as.
    pub candidate: EntityId,
    pub state: AgentHealthApplicationState,
    /// The gate's standing ruling, once it ruled: its row and disposition.
    pub verdict: Option<EntityId>,
    pub disposition: Option<String>,
    pub updated_at: u64,
}

/// The card's application after the owner's call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConcernApplyOutcome {
    /// The card's `health:` handle.
    pub card: String,
    pub application: AgentHealthCoachApplication,
}
