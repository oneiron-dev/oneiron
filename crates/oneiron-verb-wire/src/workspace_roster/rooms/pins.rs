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

/// `vault.rooms.pins.policy.set`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomPinPolicySet {
    pub room: EntityId,
    pub policy: RoomPinPolicy,
    /// The approved check-in of this member's earlier opening of another's
    /// room's pins to every member, which waited on it; the set spends it
    /// (ROLES-CHECKIN 2k8f). Omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in_ref: Option<String>,
}

/// `vault.rooms.pins.policy.set`'s reply: the stored policy, and the
/// check-in decision of a set that opened the pins to every member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomPinPolicyReply {
    pub room: EntityId,
    pub policy: RoomPinPolicy,
    /// The Owner's `own_proof`, the room's creator's `own_item`, or a
    /// member's set under their role (with the check-in it spent). None for
    /// a set that changed nothing or narrowed the pins to the managers, for
    /// a home room's (its project's leader or board sets it under room
    /// policy) and for an unjudged person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<crate::check_in::CheckInDecision>,
}
