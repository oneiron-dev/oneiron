//! Moved from `crates/oneiron/src/workspace_roster/project/extra_rooms.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::rooms::hosting::ProjectRoomPlace;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MEMORY_CODE_FORBIDDEN;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::write_envelope::WriteActor;
use serde::Deserialize;
use serde::Serialize;

/// Groups `room_ref` into `project_ref` as an extra room, or takes it out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectRoomLinkRequest {
    /// The grouping project, 32-hex.
    pub project_ref: String,
    /// The room grouped as an extra room, 32-hex.
    pub room_ref: String,
}

/// The extra-room link a link or unlink committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProjectRoomLink {
    /// The grouping project, 32-hex.
    pub project_ref: String,
    /// The grouped room, 32-hex.
    pub room_ref: String,
    /// Always `Extra`: link and unlink never touch a home room.
    pub place: ProjectRoomPlace,
}

/// Lists the rooms `project_ref` groups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectRoomsRequest {
    /// The project whose rooms are listed, 32-hex.
    pub project_ref: String,
}

/// The home room first, then the caller's readable extra rooms by room id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProjectRoomsPage {
    /// The home room first, then extra rooms by room id. No paging.
    pub rows: Vec<ProjectRoomRow>,
}

/// One room a project groups, with how it groups it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProjectRoomRow {
    /// The room, 32-hex.
    pub room_ref: String,
    /// Whether the project groups it as its home room or as an extra room.
    pub place: ProjectRoomPlace,
}
