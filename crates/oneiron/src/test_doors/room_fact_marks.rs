//! Doors for `tests/room_pins_noop_marks.rs` (FIX ROOM-PINS-NOOP-MARKS-DIRTY):
//! the sync mark a room's pin cell takes when it changed while no live
//! window carried the room, which queues the room for a flush. Compiled only
//! under `--cfg oneiron_test_support`; never API.

use crate::error::Result;
use crate::{EntityId, Vault};

/// Whether `room`'s pin cell is marked changed for the room-fact flush.
pub fn room_pin_cell_marked(vault: &Vault, room: EntityId) -> Result<bool> {
    crate::sync::room_facts::room_pin_cell_marked(vault, room)
}

/// Clears `room`'s pin cell mark, as a flush that took the cell does.
pub fn clear_room_pin_cell_mark(vault: &Vault, room: EntityId) -> Result<()> {
    crate::sync::room_facts::clear_room_pin_cell_mark(vault, room)
}
