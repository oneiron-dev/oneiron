//! Moved from `crates/oneiron/src/settings/room_threads.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The owner's two switches over Admins and private room threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomThreadAdminSettings {
    /// Whether an Admin may walk into a private thread, from now on
    /// (`rooms.private_threads.admin_walk_in`).
    pub admin_walk_in: bool,
    /// Whether an Admin may delete a private thread
    /// (`rooms.private_threads.admin_delete`).
    pub admin_delete: bool,
}
