//! Claim status axes and the scoped-read receipt. `oneiron::claim` re-exports them next
//! to the claim records and the scoped-read lane.

mod receipt;
mod status;

pub use self::receipt::{ReadScope, ScopedReadReceipt};
pub use self::status::*;

use crate::entity_id::EntityId;

/// Reserved value for base reality. This is a scope member, never an entity row.
pub fn base_world_id() -> EntityId {
    EntityId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).expect("base scope id")
}
