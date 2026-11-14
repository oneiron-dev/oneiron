//! Moved from `crates/oneiron/src/workspace_roster/rooms/pins.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::conversation_body::RoomPin;
use oneiron_store::conversation_body::RoomPinPolicy;
use serde::Deserialize;
use serde::Serialize;

/// `vault.rooms.pins.pin` and `vault.rooms.pins.unpin`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomPinRequest {
    /// The room whose shared pins change.
    pub room: EntityId,
    /// The record the pin names.
    pub target: EntityId,
}

/// `vault.rooms.pins.pin`'s reply: the room's record for the target. A
/// target pinned already keeps its first record, which this returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomPinReply {
    pub room: EntityId,
    pub pin: RoomPin,
}

/// `vault.rooms.pins.unpin`'s reply. It says nothing about whether the
/// target was pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomUnpinReply {
    pub room: EntityId,
}

/// `vault.rooms.pins.policy.set`'s input, and its reply with the stored
/// policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomPinPolicySet {
    pub room: EntityId,
    pub policy: RoomPinPolicy,
}
