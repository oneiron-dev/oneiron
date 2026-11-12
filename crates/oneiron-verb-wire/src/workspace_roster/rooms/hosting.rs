//! Moved from `crates/oneiron/src/workspace_roster/rooms/hosting.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::rooms::*;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::ClaimError;
use oneiron_base::error::RecordError;
use oneiron_base::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron_base::registry::ENTITY_TYPE_PERSON;
use oneiron_contracts::room_join::JoinSubject;

/// How a member speaks in a room. Engine upkeep holds neither role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RoomSpeakingRole {
    /// Holds the room's speaking duty.
    Host,
    /// Speaks when addressed, or when its posture lets it chime in.
    Member,
}

/// How a room's stored host came to hold it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HostPinKind {
    /// Someone the room's grant allows pinned it.
    Pinned,
    /// The room's host handed the duty on.
    HandedOff,
}

/// `vault.rooms.host.pin`: pins `agent` as `room`'s host, or with none
/// clears the room's stored host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomHostPin {
    pub room: EntityId,
    #[serde(default)]
    pub agent: Option<EntityId>,
}

/// `vault.rooms.host.hand`: the room's current host hands the duty to `to`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomHostHand {
    pub room: EntityId,
    pub to: EntityId,
    /// The live session whose participants count as present, as
    /// `vault.rooms.host` reads it. A host by presence must be one of them; a
    /// stored host hands on without one.
    #[serde(default)]
    pub session: Option<EntityId>,
}

/// Whether the project that groups a room does so as its home project or as
/// an extra room.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProjectRoomPlace {
    /// The room is the project's derived home room.
    Home,
    /// The room keeps its own members and scope; the project only groups it.
    Extra,
}
