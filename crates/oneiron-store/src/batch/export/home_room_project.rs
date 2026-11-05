//! The project a home-room body names, read by an importer to order a room
//! after its project.

use crate::conversation_body::ProjectRoom;
use oneiron_contracts::entity_id::EntityId;

/// The project a home-room body names. A derived room id carries no order
/// against its project's id, so an importer resolves the project first.
pub fn project_room_dependency(bytes: &[u8]) -> Option<EntityId> {
    let room = rmp_serde::from_slice::<ProjectRoom>(bytes).ok()?;
    EntityId::from_hex(&room.project_id).ok()
}
