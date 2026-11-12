//! Moved from `crates/oneiron/src/workspace_roster/rooms/hosting.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::join_receipt::RosterActor;
use crate::workspace_roster::rooms::*;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

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

/// A room's stored host: the latest pin or handoff. It wins outright while
/// its agent may still host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostPin {
    pub agent: EntityId,
    /// Who pinned it, or the host who handed it on; no one once that actor
    /// was erased.
    pub by: RosterActor,
    pub kind: HostPinKind,
    /// When it was recorded, on the store's recorded-at clock (unix seconds).
    pub at: u64,
}

/// Who holds a room's speaking duty now.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RoomHosting {
    /// The agent holding it; `None` when no agent may, as in a room of
    /// humans only.
    pub host: Option<EntityId>,
    /// The other present agents who may hold it by presence, earliest
    /// arrival first: the nearest present leaders, or every present agent
    /// when no leader is here. Shown, never chosen from.
    pub candidates: Vec<EntityId>,
    /// The stored pin or handoff that chose `host`; `None` when presence
    /// chose it.
    pub pin: Option<HostPin>,
}

/// A member's reading of its room's hosting and of its own speaking role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RoomStanding {
    pub hosting: RoomHosting,
    /// `None` for an actor that speaks as no persona.
    pub role: Option<RoomSpeakingRole>,
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
