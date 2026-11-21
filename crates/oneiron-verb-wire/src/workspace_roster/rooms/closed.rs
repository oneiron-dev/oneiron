//! `vault.rooms.closed.set`'s wire type (ARCH-0082 #closed-room).

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.rooms.closed.set`'s input, and its reply with the stored setting:
/// whether every add to `room_ref` asks the room's owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomClosedSet {
    /// The room to close or open.
    pub room_ref: EntityId,
    /// `true` closes the room, `false` opens it.
    pub closed: bool,
}
