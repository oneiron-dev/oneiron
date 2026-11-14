//! Moved from `crates/oneiron/src/workspace_roster/project/mod.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::workspace_roster::project::extra_rooms::ProjectRoomLink;
pub use crate::workspace_roster::project::extra_rooms::ProjectRoomLinkRequest;
pub use crate::workspace_roster::project::extra_rooms::ProjectRoomRow;
pub use crate::workspace_roster::project::extra_rooms::ProjectRoomsPage;
pub use crate::workspace_roster::project::extra_rooms::ProjectRoomsRequest;
pub use crate::workspace_roster::project::goal::GoalAxis;
pub use crate::workspace_roster::project::goal::GoalExplorationBudget;
pub use crate::workspace_roster::project::goal::GoalPreference;
pub use crate::workspace_roster::project::goal::interview::GoalInterviewTurns;
pub use crate::workspace_roster::project::goal::proposals::ProjectGoalBase;
pub use crate::workspace_roster::project::goal::proposals::ProjectGoalProposalImprovement;
pub use crate::workspace_roster::project::goal::proposals::ProjectGoalProposalReasons;
pub use crate::workspace_roster::project::mint::ProjectBudgetShare;
pub use crate::workspace_roster::project::mint::ProjectGoalRecord;
pub use crate::workspace_roster::project::proposal::ProjectCardConfirmRequest;
pub use crate::workspace_roster::project::proposal::ProjectProposalRequest;
pub use crate::workspace_roster::project::revision::ProjectRevisionHash;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::derived_domains::PROJECT_HOME_ROOM;
pub use oneiron_store::conversation_body::ProjectRoom;
pub use oneiron_store::conversation_body::RoomOriginCard;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectRole {
    Project,
    Corpus,
}

pub const fn default_depth_limit() -> u64 {
    10
}

/// One parent's head as a re-parenting state saw it (ARCH-0079 stacking):
/// the state names it, and that head's leader sits on the state's board.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectParentWitness {
    pub project: EntityId,
    pub head: ProjectRevisionHash,
    pub leader: EntityId,
}

pub fn invalid() -> Error {
    Error::InvalidConfig("invalid project or home room".into())
}

pub fn home_room_id(project: EntityId) -> Result<EntityId> {
    EntityId::derive(PROJECT_HOME_ROOM, &[project.as_bytes()])
}
pub mod extra_rooms;
pub mod goal;
pub mod mint;
pub mod proposal;
pub mod revision;
