//! Moved from `crates/oneiron/src/genui/project_proposal.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;

/// The agent supplies content and picks; the engine does not infer a project from text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalDraft {
    pub goal: String,
    pub why: String,
    pub axes: Vec<String>,
}

/// Agent-drafted roster, budget and skill choices; refs are resolved at the write gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectProposalPicks {
    pub leader_agent_def_ref: String,
    pub board_human_refs: Vec<String>,
    pub budget_share_bps: u16,
    pub starting_skill_refs: Vec<String>,
}
