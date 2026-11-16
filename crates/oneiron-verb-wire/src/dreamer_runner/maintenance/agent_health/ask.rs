//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/agent_health/ask.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_runner::maintenance::agent_health::loaded::AgentHealthSkillTarget;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The Coach's sealed-pad read for one ask. A held or refused read leaves the
/// Coach the card and the TASK alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AgentHealthPadRead {
    /// The pads were read; `read` is the agent's read-log row. `pads` counts
    /// the pads the read returned and `pad_ids` names them, in its order
    /// (FIX 5457).
    Read {
        read: Option<EntityId>,
        pads: usize,
        pad_ids: Vec<EntityId>,
    },
    /// The agent reviews reads first; `request` waits for its answer.
    PendingReview { request: EntityId },
    /// The agent said no to the Coach's reason.
    Declined { request: EntityId },
    /// The Coach does not read this agent's pads (a companion).
    NotCovered,
    /// The read door refused, with its code.
    Refused { code: String },
}

/// The fix the Coach proposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealthCoachRoute {
    /// Edit the skill the agent ran.
    SkillEdit,
    /// Inject a prompt and resume from before the trouble.
    PromptInject,
    /// Neither fits: a person should look.
    Neither,
}

/// One proposal in the Coach's words. The reader decides; only the owner's
/// approval of exact bytes applies a skill edit (`apply.rs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthCoachDraft {
    pub route: AgentHealthCoachRoute,
    /// What the Coach thinks is going on.
    pub diagnosis: String,
    /// For a skill edit, the whole replacement instructions of `target`; for
    /// a prompt injection, the exact prompt; else what a person should see.
    pub proposal: String,
    /// The loaded revision a skill edit replaces, as the apply door takes it.
    /// `None` for another route, or when the Coach named no revision the
    /// card's run loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<AgentHealthSkillTarget>,
}
