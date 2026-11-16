//! Moved from `crates/oneiron/src/workspace_roster/rooms/replica.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;

/// `hex` as an id, when it is one's canonical spelling.
pub fn named(hex: &str) -> Option<EntityId> {
    EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
}
