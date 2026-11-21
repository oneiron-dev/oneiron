//! The owner's two switches over Admins and private room threads (owner
//! ruling 2026-10-20, FIX 6382): whether an Admin may walk into a private
//! thread, and whether an Admin may delete one. Both are owner policy, set
//! by the Owner alone, and absent reads ON: a vault that never wrote either
//! lets its Admins do both. The Owner never depends on either switch.

use crate::authority::OwnerProofGround;
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
};
use crate::batch::export::{ArchiveRetainedSideRow, OwnerArchiveRestorePermit};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::world_keys::{OwnerActImportance, owner_presence_reasons};
use crate::{EntityId, Vault};

/// The owner setting key of the walk-in switch, as a refusal names it. The
/// delete switch's is `rooms.private_threads.admin_delete`.
pub(crate) const ROOM_THREADS_ADMIN_WALK_IN_KEY: &str = "rooms.private_threads.admin_walk_in";

/// Whether an Admin may walk into a private thread. Absent is on.
const ADMIN_WALK_IN: SideTable<(), bool, Named> =
    SideTable::new(&side_table::ROOM_THREADS_ADMIN_WALK_IN);

/// Whether an Admin may delete a private thread. Absent is on.
const ADMIN_DELETE: SideTable<(), bool, Named> =
    SideTable::new(&side_table::ROOM_THREADS_ADMIN_DELETE);

#[doc(hidden)]
pub use oneiron_records::settings::room_threads::RoomThreadAdminSettings;

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

/// What [`Vault::set_room_thread_admin_settings`]'s checks establish before
/// its first write, on one snapshot: the owner, the switches in force, the
/// switches after the set, and the importance the act asks with.
struct RoomThreadAdminSettingsChecks {
    actor: EntityId,
    prior: RoomThreadAdminSettings,
    settings: RoomThreadAdminSettings,
    importance: OwnerActImportance,
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
    /// records nothing. Answers the two as they now read. When `surface` names an
    /// act, the door checks on a read before it asks. Only turning on an off
    /// switch is important. The write derives importance again and answers
    /// [`Error::ConcurrentWrite`](crate::error::Error::ConcurrentWrite) when
    /// the act became more important since the person was asked.
    pub fn set_room_thread_admin_settings(
        &self,
        owner: &AuthenticatedOwner,
        surface: Option<crate::authority::ActSurface>,
        admin_walk_in: Option<bool>,
        admin_delete: Option<bool>,
    ) -> Result<RoomThreadAdminSettings> {
        self.set_room_thread_admin_settings_between(
            owner,
            surface,
            admin_walk_in,
            admin_delete,
            || {},
        )
    }

    /// [`Self::set_room_thread_admin_settings`], with `between` run after the
    /// door asked and before its write opens: the gap in which another writer
    /// can commit first (the test door `test_doors::policy_doors_between`).
    pub(crate) fn set_room_thread_admin_settings_between(
        &self,
        owner: &AuthenticatedOwner,
        surface: Option<crate::authority::ActSurface>,
        admin_walk_in: Option<bool>,
        admin_delete: Option<bool>,
        between: impl FnOnce(),
    ) -> Result<RoomThreadAdminSettings> {
        // A surface names an act. The read checks it and drops before the
        // door asks. With no surface the door goes straight to its write.
        let ground = if surface.is_some() {
            let importance = {
                let txn = self.store.env.read_txn()?;
                self.room_thread_admin_settings_checks_in_txn(
                    &txn,
                    owner,
                    admin_walk_in,
                    admin_delete,
                )?
                .importance
            };
            let _ = importance;
            let witness = self.owner_presence(
                OwnerActImportance::Important,
                owner_presence_reasons::ROOM_THREAD_ADMIN,
            )?;
            Some(OwnerProofGround::witnessed(&witness))
        } else {
            None
        };
        between();
        self.with_write_txn_grouped(|txn| {
            let RoomThreadAdminSettingsChecks {
                actor,
                prior,
                settings,
                importance,
            } = self.room_thread_admin_settings_checks_in_txn(
                txn,
                owner,
                admin_walk_in,
                admin_delete,
            )?;
            if let Some(ground) = &ground {
                ground.refuse_risen_importance(importance)?;
            }
            if settings.admin_walk_in != prior.admin_walk_in {
                ADMIN_WALK_IN.put(&self.store, txn, &(), &settings.admin_walk_in)?;
            }
            if settings.admin_delete != prior.admin_delete {
                ADMIN_DELETE.put(&self.store, txn, &(), &settings.admin_delete)?;
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
                    self.record_policy_setting_op_in_txn(txn, ground.as_ref(), act);
                }
            }
            Ok(settings)
        })
    }

    /// Every check [`Self::set_room_thread_admin_settings`] makes before its
    /// first write, in the order the write makes them, with the importance
    /// the act asks with. It runs on a read before the door asks and again
    /// in the write, so a refusal raises no prompt.
    fn room_thread_admin_settings_checks_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
        admin_walk_in: Option<bool>,
        admin_delete: Option<bool>,
    ) -> Result<RoomThreadAdminSettingsChecks> {
        let actor = owner.revalidate_in_txn(self, txn)?;
        let prior = room_thread_admin_settings_in_txn(self, txn)?;
        let settings = RoomThreadAdminSettings {
            admin_walk_in: admin_walk_in.unwrap_or(prior.admin_walk_in),
            admin_delete: admin_delete.unwrap_or(prior.admin_delete),
        };
        Ok(RoomThreadAdminSettingsChecks {
            actor,
            prior,
            settings,
            importance: OwnerActImportance::of_direction(settings.direction_from(prior)),
        })
    }
}

/// Lands one archived admin-delete envelope: an absent-key exact-bytes install, leaving the walk-in
/// key alone.
pub(super) fn land_archived_room_threads_admin_delete_row_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    row: &ArchiveRetainedSideRow,
) -> Result<ArchivedSideRowOutcome> {
    land_room_thread_admin_flag_row_in_txn(&ADMIN_DELETE, vault, txn, permit, row)
}

/// Lands one archived admin walk-in envelope: an absent-key exact-bytes install, leaving the delete
/// key alone.
pub(super) fn land_archived_room_threads_admin_walk_in_row_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    row: &ArchiveRetainedSideRow,
) -> Result<ArchivedSideRowOutcome> {
    land_room_thread_admin_flag_row_in_txn(&ADMIN_WALK_IN, vault, txn, permit, row)
}

/// Lands one archived admin-switch envelope through `table`: the writer takes any bool, so decoding
/// plus an absent-key exact-bytes install is the whole check.
fn land_room_thread_admin_flag_row_in_txn(
    table: &SideTable<(), bool, Named>,
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    row: &ArchiveRetainedSideRow,
) -> Result<ArchivedSideRowOutcome> {
    let (key, _) = match decode_archived_row(table, row) {
        Ok(decoded) => decoded,
        Err(reason) => return Ok(ArchivedSideRowOutcome::HeldBack(reason)),
    };
    install_archived_row(table, vault, txn, permit, &key, row)
}
