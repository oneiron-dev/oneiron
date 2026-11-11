//! Doors for `tests/feed_erase_doors.rs`: the change feed rows that name an entity, which an
//! erase leaves at none whatever a reader's lane shows (review #6942). A reader is told nothing
//! of rows its lane does not show (lead call K), so the count is read here.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// How many edge, redirty and withdrawn-type feed rows name `id`.
///
/// # Errors
///
/// The read.
pub fn rows_naming(vault: &Vault, id: &EntityId) -> Result<usize> {
    crate::feeds::rows_naming(vault, id)
}
