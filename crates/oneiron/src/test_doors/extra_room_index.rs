//! Doors for `tests/checkpoint_restore_derived_index_rebuild.rs`: drop one
//! room's extra-room index row while its body keeps the `project_group` key,
//! as a checkpoint image cut before the index holds the room.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{Raw, SideTable};

/// The extra-room index by its declared table, as
/// `workspace_roster::project::EXTRA_ROOM_PROJECT` binds it.
const EXTRA_ROOM_PROJECT: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&crate::side_table::PROJECT_EXTRA_ROOM);

/// Drops the extra-room index row of `room`; `true` when one was there. The
/// room body is untouched, so a checkpoint cut now carries the room's
/// `project_group` key without the derived row, as an image cut before the
/// index does.
///
/// # Errors
///
/// The vault's.
pub fn drop_extra_room_row(vault: &Vault, room: EntityId) -> Result<bool> {
    vault.with_write_txn_grouped(|txn| EXTRA_ROOM_PROJECT.delete(&vault.store, txn, &room))
}
