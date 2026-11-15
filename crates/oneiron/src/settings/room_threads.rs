//! The owner's two switches over Admins and private room threads (owner
//! ruling 2026-10-20, FIX 6382): whether an Admin may walk into a private
//! thread, and whether an Admin may delete one. Both are owner policy, set
//! by the Owner alone, and absent reads ON: a vault that never wrote either
//! lets its Admins do both. The Owner never depends on either switch. Each
//! is a catalogue key (`settings::setting_keys`), which the Owner sets
//! through `vault.settings.set`.

use serde::{Deserialize, Serialize};

use super::setting_keys::{ROOM_THREADS_ADMIN_DELETE, ROOM_THREADS_ADMIN_WALK_IN};
use crate::Vault;
use crate::error::Result;

/// The owner setting key of the walk-in switch, as a refusal names it. The
/// delete switch's is `rooms.private_threads.admin_delete`.
pub(crate) const ROOM_THREADS_ADMIN_WALK_IN_KEY: &str = "rooms.private_threads.admin_walk_in";

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

/// The two switches in `txn`, each absent read ON: the one reader every
/// gate over Admins and private threads reads in its own write.
pub(crate) fn room_thread_admin_settings_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<RoomThreadAdminSettings> {
    Ok(RoomThreadAdminSettings {
        admin_walk_in: ROOM_THREADS_ADMIN_WALK_IN
            .read_in_txn(vault, txn, &[], None)?
            .value,
        admin_delete: ROOM_THREADS_ADMIN_DELETE
            .read_in_txn(vault, txn, &[], None)?
            .value,
    })
}

impl Vault {
    /// The owner's two switches over Admins and private room threads, each
    /// absent read ON.
    pub fn room_thread_admin_settings(&self) -> Result<RoomThreadAdminSettings> {
        let rtxn = self.store.env.read_txn()?;
        room_thread_admin_settings_in_txn(self, &rtxn)
    }
}
