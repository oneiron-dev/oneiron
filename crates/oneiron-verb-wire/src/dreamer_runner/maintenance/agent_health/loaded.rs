//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/agent_health/loaded.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The revision a `skill_edit` draft replaces whole: one the card's run
/// loaded, named as the apply door takes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthSkillTarget {
    /// The SKILL revision, as 32 hex.
    pub skill: String,
    pub version: String,
}
