//! Moved from `crates/oneiron/src/genui/project_proposal.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
pub use oneiron_verb_wire::genui::project_proposal::ProjectGoalDraft;
pub use oneiron_verb_wire::genui::project_proposal::ProjectProposalPicks;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;

pub const PROJECT_PROPOSAL_MINT_ACTION_ID: &str = "mint_project";

/// A validated trigger, not a project row or permission to write one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectMintIntent {
    pub principal_ref: String,
    pub origin_component_id: String,
    pub origin_action_id: String,
    pub source_message_ref: String,
    pub source_room_ref: Option<String>,
    pub source_thread_ref: Option<String>,
    pub goal: ProjectGoalDraft,
    pub leader_agent_def_ref: String,
    pub board_human_refs: Vec<String>,
    pub budget_share_bps: u16,
    pub starting_skill_refs: Vec<String>,
}

/// A ref must agree byte-for-byte with the store-authenticated principal or
/// downstream ID resolver; prose is deliberately not normalized here.
pub fn ensure_canonical_ref(name: &str, reference: &str) -> Result<()> {
    if reference != reference.trim() {
        return Err(Error::InvalidConfig(format!(
            "project proposal {name} must not have surrounding whitespace"
        )));
    }
    Ok(())
}
