//! Core half of `settings::room_threads`: its store-layer items live in `oneiron_store::settings::room_threads` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::settings::room_threads::*;

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use serde::{Deserialize, Serialize};

/// Whether an Admin may walk into a private thread. Absent is on.
const ADMIN_WALK_IN: SideTable<(), bool, Named> =
    SideTable::new(&side_table::ROOM_THREADS_ADMIN_WALK_IN);

/// Whether an Admin may delete a private thread. Absent is on.
const ADMIN_DELETE: SideTable<(), bool, Named> =
    SideTable::new(&side_table::ROOM_THREADS_ADMIN_DELETE);

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
    /// changes is written. A change records the owner's act with the
    /// settings it replaces when `surface` names where the owner said so
    /// (FIX 6465), in the same commit; a request that changes nothing
    /// records nothing. Answers the two as they now read.
    pub fn set_room_thread_admin_settings(
        &self,
        owner: &AuthenticatedOwner,
        surface: Option<crate::authority::ActSurface>,
        admin_walk_in: Option<bool>,
        admin_delete: Option<bool>,
    ) -> Result<RoomThreadAdminSettings> {
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let prior = room_thread_admin_settings_in_txn(self, txn)?;
            let mut settings = prior;
            if let Some(on) = admin_walk_in.filter(|on| *on != settings.admin_walk_in) {
                ADMIN_WALK_IN.put(&self.store, txn, &(), &on)?;
                settings.admin_walk_in = on;
            }
            if let Some(on) = admin_delete.filter(|on| *on != settings.admin_delete) {
                ADMIN_DELETE.put(&self.store, txn, &(), &on)?;
                settings.admin_delete = on;
            }
            if settings != prior {
                let signed = crate::policy_setting_doors::record_policy_setting_act_in_txn(
                    self,
                    txn,
                    crate::policy_setting_doors::PolicySetting::RoomThreadAdmin,
                    actor,
                    surface,
                    &prior,
                    &settings,
                )?;
                // The signed record goes last, best effort (FIX 4624).
                if let Some(act) = signed {
                    self.record_policy_setting_op_in_txn(txn, act);
                }
            }
            Ok(settings)
        })
    }
}
