//! The owner's two switches over Admins and private room threads (owner
//! ruling 2026-10-20, FIX 6382): whether an Admin may walk into a private
//! thread, and whether an Admin may delete one. Both are owner policy, set
//! by the Owner alone, and absent reads ON: a vault that never wrote either
//! lets its Admins do both. The Owner never depends on either switch.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// The owner setting key of the walk-in switch, as a refusal names it. The
/// delete switch's is `rooms.private_threads.admin_delete`.
pub(crate) const ROOM_THREADS_ADMIN_WALK_IN_KEY: &str = "rooms.private_threads.admin_walk_in";

/// Whether an Admin may walk into a private thread. Absent is on.
const ADMIN_WALK_IN: SideTable<(), bool, Named> =
    SideTable::new(&side_table::ROOM_THREADS_ADMIN_WALK_IN);

/// Whether an Admin may delete a private thread. Absent is on.
const ADMIN_DELETE: SideTable<(), bool, Named> =
    SideTable::new(&side_table::ROOM_THREADS_ADMIN_DELETE);

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
        admin_walk_in: ADMIN_WALK_IN.get(&vault.store, txn, &())?.unwrap_or(true),
        admin_delete: ADMIN_DELETE.get(&vault.store, txn, &())?.unwrap_or(true),
    })
}

impl Vault {
    /// The owner's two switches over Admins and private room threads, each
    /// absent read ON.
    pub fn room_thread_admin_settings(&self) -> Result<RoomThreadAdminSettings> {
        let rtxn = self.store.env.read_txn()?;
        room_thread_admin_settings_in_txn(self, &rtxn)
    }

    /// The owner sets either switch, or both; `None` leaves one as it is.
    /// The Owner is revalidated in the writer, and only a switch that
    /// changes is written. Answers the two as they now read.
    pub fn set_room_thread_admin_settings(
        &self,
        owner: &AuthenticatedOwner,
        admin_walk_in: Option<bool>,
        admin_delete: Option<bool>,
    ) -> Result<RoomThreadAdminSettings> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let mut settings = room_thread_admin_settings_in_txn(self, txn)?;
            if let Some(on) = admin_walk_in.filter(|on| *on != settings.admin_walk_in) {
                ADMIN_WALK_IN.put(&self.store, txn, &(), &on)?;
                settings.admin_walk_in = on;
            }
            if let Some(on) = admin_delete.filter(|on| *on != settings.admin_delete) {
                ADMIN_DELETE.put(&self.store, txn, &(), &on)?;
                settings.admin_delete = on;
            }
            Ok(settings)
        })
    }
}
