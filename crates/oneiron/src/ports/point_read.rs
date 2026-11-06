//! Core half of `ports::point_read`: its store-layer items live in `oneiron_store::ports::point_read` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::ports::point_read::*;

use crate::vault::ReadMode;
use crate::{EntityId, HydratedShortIdDeletion, TimeRange};

/// One admitted row.
///
/// An id read admits a row only with its body. A short reference may also
/// resolve to a deleted shell: `body` is then `None` and `deletion` carries the
/// deletion metadata this actor may see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRow {
    pub id: EntityId,
    pub entity_type: u8,
    pub occurred: TimeRange,
    pub learned_at: u64,
    pub body: Option<Vec<u8>>,
    pub deletion: Option<HydratedShortIdDeletion>,
    /// The content-hash byte of the stored revision this row was read from,
    /// the byte an engine-issued short reference to that revision carries.
    pub content_hash: u8,
}
