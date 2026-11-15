//! Moved from `crates/oneiron/src/workspace_roster/project/mod.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::workspace_roster::project::asks::ProjectAsk;
pub use crate::workspace_roster::project::fold::ProjectForkConflict;
pub use crate::workspace_roster::project::fold::ProjectRank;
pub use crate::workspace_roster::project::goal::proposals::ProjectGoalProposalDismissal;
pub use crate::workspace_roster::project::goal::proposals::ProjectGoalProposalRate;
pub use crate::workspace_roster::project::goal::proposals::ProjectGoalProposalStatus;
pub use crate::workspace_roster::project::goal::proposals::diff::GoalAxisChange;
pub use crate::workspace_roster::project::goal::proposals::diff::GoalAxisChanges;
pub use crate::workspace_roster::project::goal::proposals::diff::GoalBudgetChange;
pub use crate::workspace_roster::project::goal::proposals::diff::GoalPreferenceChange;
pub use crate::workspace_roster::project::goal::proposals::diff::GoalPreferenceChanges;
pub use crate::workspace_roster::project::goal::proposals::diff::GoalTextChange;
pub use crate::workspace_roster::project::history_policy::DEFAULT_PROJECT_CYCLE_WORLDS_MAX;
pub use crate::workspace_roster::project::history_policy::DEFAULT_PROJECT_HISTORY_MAX_REVISIONS;
pub use crate::workspace_roster::project::history_policy::ProjectCycleQuestion;
pub use crate::workspace_roster::project::history_policy::ProjectHistoryOverBudget;
pub use crate::workspace_roster::project::history_policy::ProjectHistoryPolicy;
pub use crate::workspace_roster::project::history_policy::ProjectHistoryQuestion;
pub use crate::workspace_roster::project::leader_chat::LeaderChat;
pub use crate::workspace_roster::project::mint::ProjectMintReceipt;
pub use crate::workspace_roster::project::proposal::ProjectCardState;
pub use crate::workspace_roster::project::resolution::ProjectResolution;
pub use crate::workspace_roster::project::resolution::ProjectSeal;
pub use crate::workspace_roster::project::widen::ProjectWidenAsk;
pub use crate::workspace_roster::project::widen::ProjectWidenAxis;
use oneiron_base::error::Result;
pub use oneiron_store::conversation_body::ProjectRoom;
pub use oneiron_store::conversation_body::RoomOriginCard;
pub use oneiron_verb_wire::workspace_roster::project::ProjectParentWitness;
pub use oneiron_verb_wire::workspace_roster::project::ProjectRole;
pub use oneiron_verb_wire::workspace_roster::project::extra_rooms::ProjectRoomLink;
pub use oneiron_verb_wire::workspace_roster::project::extra_rooms::ProjectRoomLinkRequest;
pub use oneiron_verb_wire::workspace_roster::project::extra_rooms::ProjectRoomRow;
pub use oneiron_verb_wire::workspace_roster::project::extra_rooms::ProjectRoomsPage;
pub use oneiron_verb_wire::workspace_roster::project::extra_rooms::ProjectRoomsRequest;
pub use oneiron_verb_wire::workspace_roster::project::goal::GoalAxis;
pub use oneiron_verb_wire::workspace_roster::project::goal::GoalExplorationBudget;
pub use oneiron_verb_wire::workspace_roster::project::goal::GoalPreference;
pub use oneiron_verb_wire::workspace_roster::project::goal::interview::GoalInterviewTurns;
pub use oneiron_verb_wire::workspace_roster::project::goal::proposals::ProjectGoalBase;
pub use oneiron_verb_wire::workspace_roster::project::goal::proposals::ProjectGoalProposalImprovement;
pub use oneiron_verb_wire::workspace_roster::project::goal::proposals::ProjectGoalProposalReasons;
pub(super) use oneiron_verb_wire::workspace_roster::project::invalid;
pub use oneiron_verb_wire::workspace_roster::project::mint::ProjectBudgetShare;
pub use oneiron_verb_wire::workspace_roster::project::mint::ProjectGoalRecord;
pub use oneiron_verb_wire::workspace_roster::project::proposal::ProjectCardConfirmRequest;
pub use oneiron_verb_wire::workspace_roster::project::proposal::ProjectProposalRequest;
pub use oneiron_verb_wire::workspace_roster::project::revision::ProjectRevisionHash;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRoomChange {
    pub project_id: String,
    pub room_id: String,
    pub previous_members: Vec<String>,
    pub member_ids: Vec<String>,
    pub at: u64,
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| invalid())
}
pub mod asks;
pub mod fold;
pub mod goal;
pub mod history_policy;
pub mod leader_chat;
pub mod mint;
pub mod proposal;
pub mod resolution;
pub mod revision;
pub mod widen;
