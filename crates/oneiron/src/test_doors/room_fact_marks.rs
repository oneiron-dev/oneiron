//! Doors for `tests/room_pins_noop_marks.rs` (FIX ROOM-PINS-NOOP-MARKS-DIRTY):
//! the sync mark a room's host-pin cell takes when a room-cell refresh with
//! no handle ran while no live window carried the room, which queues the
//! room for a flush. The pin and pin-policy doors run that refresh. Compiled only
//! under `--cfg oneiron_test_support`; never API.

use crate::error::Result;
use crate::{EntityId, Vault};

/// Whether `room`'s host-pin cell is marked changed for the room-fact
/// flush.
pub fn room_host_pin_cell_marked(vault: &Vault, room: EntityId) -> Result<bool> {
    crate::sync::room_facts::room_host_pin_cell_marked(vault, room)
}

/// Clears `room`'s host-pin cell mark, as an import that carries the cell
/// does.
pub fn clear_room_host_pin_cell_mark(vault: &Vault, room: EntityId) -> Result<()> {
    crate::sync::room_facts::clear_room_host_pin_cell_mark(vault, room)
}
