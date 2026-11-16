//! Moved from `crates/oneiron/src/workspace_roster/project/proposal.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::genui::project_proposal::ProjectGoalDraft;
use crate::genui::project_proposal::ProjectProposalPicks;
use serde::Deserialize;
use serde::Serialize;

/// What the drafting agent proposes on one source message. The principal and
/// the thread placement come from the detection, never from the request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectProposalRequest {
    pub card_id: String,
    pub source_message_ref: String,
    pub goal: ProjectGoalDraft,
    pub picks: ProjectProposalPicks,
}

/// A tap on a host-held card. The host binds the authenticated owner, the
/// actor, the surface and the owner signer; none of them travel here.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectCardConfirmRequest {
    pub card_id: String,
    /// The card action tapped (`mint_project`).
    pub action_id: String,
    pub occurred_at: u64,
}
