//! Doors for `tests/room_turn_backfill.rs` (THREAD-TASK-EVERY-ROOM P2): strip
//! a room's rows to the state a vault older than P1 held, read the rows, the
//! indexes and the marker raw, count the room wakes, and run the open's
//! backfill pass again.

use crate::error::Result;
use crate::workspace_roster::RoomTurn;
use crate::workspace_roster::room_turn_backfill_doors as doors;
use crate::{EntityId, Vault};

/// The backfill version a room's marker holds once the pass rowed it.
pub const ROOM_TURN_BACKFILL_VERSION: u64 = doors::ROOM_TURN_BACKFILL_VERSION;

/// What one backfill pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BackfillCounts {
    /// Rooms the pass marked complete.
    pub rooms_completed: u64,
    /// Rooms left unmarked for a later open.
    pub rooms_deferred: u64,
    /// Rows the pass wrote.
    pub turns_written: u64,
    /// TURNs that already kept a row.
    pub turns_present: u64,
    /// Erased TURNs left with no row.
    pub skipped_erased: u64,
    /// TURNs that recorded no writer, left with no row.
    pub skipped_no_writer: u64,
    /// Thread TURNs with no anchor or parent, left with no row.
    pub skipped_unbound: u64,
    /// A home room's witness TURNs with no row, left with none.
    pub skipped_home_witness: u64,
    /// TURNs whose body or DAG parent does not decode, left with no row.
    pub skipped_undecodable: u64,
}

/// A room's index rows, each list in key order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoomIndexRows {
    /// `(at, turn)` of every HISTORY row.
    pub history: Vec<(u64, EntityId)>,
    /// `(at, turn)` of every HEADS row.
    pub heads: Vec<(u64, EntityId)>,
    /// `(anchor, turn)` of every THREAD_CHILDREN row.
    pub thread_children: Vec<(EntityId, EntityId)>,
}

/// Removes the room row and its index rows of every rowed TURN of `room`
/// not in `keep`, and the room's marker. Returns the count.
pub fn strip_room_turn_rows(vault: &Vault, room: EntityId, keep: &[EntityId]) -> Result<u64> {
    doors::strip_room_turn_rows(vault, room, keep)
}

/// Every room row of `room`, raw, in HISTORY order.
pub fn room_turn_rows(vault: &Vault, room: EntityId) -> Result<Vec<RoomTurn>> {
    doors::room_turn_rows(vault, room)
}

/// The room row of `turn`, raw.
pub fn room_turn_row(vault: &Vault, turn: EntityId) -> Result<Option<RoomTurn>> {
    doors::room_turn_row(vault, turn)
}

/// Puts `row` as the room row of its TURN, with no index change.
pub fn put_room_turn_row(vault: &Vault, row: &RoomTurn) -> Result<()> {
    doors::put_room_turn_row(vault, row)
}

/// `room`'s HISTORY, HEADS and THREAD_CHILDREN rows.
pub fn room_index_rows(vault: &Vault, room: EntityId) -> Result<RoomIndexRows> {
    let (history, heads, thread_children) = doors::room_index_rows(vault, room)?;
    Ok(RoomIndexRows {
        history,
        heads,
        thread_children,
    })
}

/// `room`'s backfill marker.
pub fn room_turn_backfill_marker(vault: &Vault, room: EntityId) -> Result<Option<u64>> {
    doors::room_turn_backfill_marker(vault, room)
}

/// The pass a writable open runs, run again on `vault`.
pub fn run_room_turn_backfill(vault: &Vault) -> Result<BackfillCounts> {
    let report = crate::workspace_roster::backfill_room_turns_on_open(vault)?;
    Ok(BackfillCounts {
        rooms_completed: report.rooms_completed,
        rooms_deferred: report.rooms_deferred,
        turns_written: report.turns_written,
        turns_present: report.turns_present,
        skipped_erased: report.skipped_erased,
        skipped_no_writer: report.skipped_no_writer,
        skipped_unbound: report.skipped_unbound,
        skipped_home_witness: report.skipped_home_witness,
        skipped_undecodable: report.skipped_undecodable,
    })
}

/// Every room wake attempt row, in any state.
pub fn room_wake_attempt_rows(vault: &Vault) -> Result<u64> {
    doors::room_wake_attempt_rows(vault)
}
