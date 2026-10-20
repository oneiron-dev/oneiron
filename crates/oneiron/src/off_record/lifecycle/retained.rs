//! A room stretch's memory, charged to its host's retained-memory line
//! (SCAN C029, FIX 5991). The host queues for [`room_entry_bytes`] before the
//! stretch is entered, outside every engine and registry lock, and hands its
//! charge in ([`OffRecordSessionVault::enter_in_room_charged`]). The stretch
//! then moves that charge to what it holds, its entry and its overlay, as
//! the overlay grows and shrinks, and the charge goes with the overlay once
//! a real close has drained it and the last handle let it go. Moving it never
//! waits and never refuses: the engine owns only this opaque interface, and
//! no member or stretch count is bounded.
//!
//! [`OffRecordSessionVault::enter_in_room_charged`]: super::OffRecordSessionVault::enter_in_room_charged
use std::mem::size_of;

use super::registry::OffRecordSessionEntry;
use super::room::ROOM_KEY_PREFIX;
use super::types::OffRecordSessionRecord;
use crate::session_overlay::SessionOverlay;

/// A B-tree map entry's share of its node: room for a sparse node's unused
/// slots, the node header and its edges.
const MAP_ENTRY_OVERHEAD: usize = 32;

/// The host's charge for one room stretch's memory, reserved on its
/// retained-memory line before the stretch was entered. Dropping it hands
/// its bytes back.
pub trait RetainedCharge: Send + Sync {
    /// Moves the charge to `bytes`, now. It never waits and never refuses:
    /// the memory it stands for is already held.
    fn charge(&self, bytes: usize);
}

/// The bytes a room stretch named `session_ref` holds once entered, before
/// its overlay holds a row: its registry entry and the record published
/// beside it, its overlay's empty state, and its key, kept in the entry's
/// record, the registry and the registry's published copy.
#[must_use]
pub fn room_entry_bytes(session_ref: &str) -> usize {
    // `room_session_key`: the prefix, the room's 32 hex and a colon.
    let key = ROOM_KEY_PREFIX
        .len()
        .saturating_add(33)
        .saturating_add(session_ref.len());
    let registered = size_of::<String>()
        .saturating_add(size_of::<std::sync::Arc<OffRecordSessionEntry>>())
        .saturating_add(MAP_ENTRY_OVERHEAD)
        .saturating_add(key);
    size_of::<OffRecordSessionEntry>()
        .saturating_add(size_of::<OffRecordSessionRecord>())
        .saturating_add(SessionOverlay::empty_bytes())
        .saturating_add(key)
        .saturating_add(registered.saturating_mul(2))
}
