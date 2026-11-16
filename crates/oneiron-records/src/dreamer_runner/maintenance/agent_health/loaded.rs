//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/agent_health/loaded.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::dreamer_runner::maintenance::agent_health::loaded::AgentHealthSkillTarget;
use serde::Deserialize;
use serde::Serialize;

/// One skill revision the card's run loaded, as the card's reader and the
/// Coach read it: the target the apply door takes, and what it says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHealthLoadedSkill {
    /// The SKILL revision, as 32 hex: the apply door's `skill`.
    pub skill: String,
    /// Its stable name, the pack manifest's `skill_id`.
    pub name: String,
    /// The version the pack pinned: the apply door's `version`.
    pub version: String,
    /// Whether it is still the skill's active revision. Only an active one
    /// takes an edit; a superseded one names what the run ran.
    pub active: bool,
    /// Its instructions, whole: what a `skill_edit` replaces.
    pub instructions: String,
}
