//! The owner's two switches over Admins and private room threads (owner
//! ruling 2026-10-20, FIX 6382): whether an Admin may walk into a private
//! thread, and whether an Admin may delete one. Both are owner policy, set
//! by the Owner alone, and absent reads ON: a vault that never wrote either
//! lets its Admins do both. The Owner never depends on either switch.

use serde::{Deserialize, Serialize};

use oneiron_base::error::Result;

/// The owner setting key of the walk-in switch, as a refusal names it. The
/// delete switch's is `rooms.private_threads.admin_delete`.
pub const ROOM_THREADS_ADMIN_WALK_IN_KEY: &str = "rooms.private_threads.admin_walk_in";

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

