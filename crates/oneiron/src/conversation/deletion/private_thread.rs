//! A private thread's delete by the vault's Owner or an Admin (owner ruling
//! 2026-10-20, FIX 6381, 6382): "The Owner and Admins can ... DELETE", and
//! the Owner's `rooms.private_threads.admin_delete` switches it off for
//! Admins.
//!
//! The authority is one record's, never a role in the room: a strictly
//! resolved private root of this canonical room, and that root's own
//! MESSAGEs its delete selects. No sibling, public thread or other record
//! of the room is reached by it. The human vault Owner always holds it, and
//! a human Admin while the switch is on. An Admin's policy delete of such a
//! record while the switch is off is refused before any room role answers,
//! a seated room Admin's included; an Admin's own author delete is not a
//! policy delete and stays as it was. So is a seated room Owner's or
//! Admin's, by room role alone, who is neither the vault's Owner nor an
//! Admin and is not in the thread's audience now (FIX 6504): the switch is
//! not passed by a room role. With the switch on that role deletes as it
//! did. Every legal hold check of the rail runs as before.

use super::*;
use crate::settings::room_threads::room_thread_admin_settings_in_txn;
use crate::workspace_roster::VaultStanding;

/// The Owner's switch over Admins deleting private threads, as its refusal
/// names it.
const ROOM_THREADS_ADMIN_DELETE_KEY: &str = "rooms.private_threads.admin_delete";

/// Who deletes a private thread's root, or one of its own messages, by the
/// ruling's authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ThreadDelete {
    /// The human vault Owner.
    Owner,
    /// A human Admin, while the Owner's switch allows it.
    Admin,
}

impl ThreadDelete {
    /// The role the delete's gate context names for this record alone.
    pub(super) const fn role(self) -> RoomRole {
        match self {
            Self::Owner => RoomRole::Owner,
            Self::Admin => RoomRole::Admin,
        }
    }
}

/// The private thread root `record` is, or whose own MESSAGE it is, in
/// `room`; `None` for any other record.
fn private_root_of(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
) -> Result<Option<EntityId>> {
    let turn = match vault.get_entity_type_in_txn(txn, &record)? {
        Some(ENTITY_TYPE_TURN) => record,
        Some(ENTITY_TYPE_MESSAGE) => {
            let parts = crate::conversation_dag::edge_ids(
                &vault.store,
                txn,
                &record,
                EdgeKind::PartOf,
                false,
                2,
            )?;
            match parts.as_slice() {
                [turn] => *turn,
                _ => return Ok(None),
            }
        }
        _ => return Ok(None),
    };
    Ok(crate::workspace_roster::private_root_of_room_in(vault, txn, room, turn)?.then_some(turn))
}

/// For a policy delete of `record` in `room` by `actor`: the authority the
/// vault's Owner or an Admin holds over a private thread's root and its
/// own messages, as a person (FIX 6381). `None` for any other record or
/// actor. An Admin, a pen of one included, is refused while the Owner's
/// switch is off (FIX 6382), whatever room role it holds, and so is a
/// seated room Owner or Admin who is neither and is not in the thread
/// (FIX 6504). A record whose thread does not read is no private root
/// here, logged: this read never fails a delete that does not reach one.
pub(super) fn private_thread_delete_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
    actor: WriteActor,
) -> Result<Option<ThreadDelete>> {
    let root = match private_root_of(vault, txn, room, record) {
        Ok(Some(root)) => root,
        Ok(None) => return Ok(None),
        Err(error) => {
            tracing::warn!(
                record = %record.to_hex(),
                %error,
                "room record delete: its private thread not read"
            );
            return Ok(None);
        }
    };
    let held = match crate::workspace_roster::vault_standing_in(vault, txn, actor.entity_ref())? {
        None => {
            if !room_thread_admin_settings_in_txn(vault, txn)?.admin_delete
                && room_role_outside_in(vault, txn, room, root, actor)
            {
                return Err(admin_delete_off());
            }
            return Ok(None);
        }
        Some(VaultStanding::Owner) => ThreadDelete::Owner,
        Some(VaultStanding::Admin) => {
            if !room_thread_admin_settings_in_txn(vault, txn)?.admin_delete {
                return Err(admin_delete_off());
            }
            ThreadDelete::Admin
        }
    };
    if actor.actor_class() != crate::EdgeActorClass::Human {
        return Ok(None);
    }
    authorize(vault, txn, actor)?;
    Ok(Some(held))
}

/// The refusal of a private thread's policy delete while the Owner's
/// switch is off (FIX 6382, 6504), naming the setting.
fn admin_delete_off() -> Error {
    Error::Refused(format!(
        "the Owner's setting {ROOM_THREADS_ADMIN_DELETE_KEY} is off: an Admin may not delete a private thread; ask the Owner to delete it or to turn the setting on"
    ))
}

/// Whether `actor` holds a room Owner or Admin role in `room`, seated, and
/// is not in the audience of the private thread rooted at `root` now, a
/// pen through its PERSON (FIX 6504). A role that does not read is no such
/// role, and an audience that does not read is logged and refuses nothing:
/// this read never fails a delete it does not refuse.
fn room_role_outside_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    root: EntityId,
    actor: WriteActor,
) -> bool {
    if !matches!(
        roles::role_in(vault, txn, room, actor),
        Ok(RoomRole::Owner | RoomRole::Admin)
    ) {
        return false;
    }
    let inside = match crate::workspace_roster::thread_audience_now_in(vault, txn, room, root) {
        Ok(Some(audience)) => {
            crate::workspace_roster::names_actor_in(vault, txn, &audience, actor.entity_ref())
        }
        Ok(None) => return false,
        Err(error) => Err(error),
    };
    match inside {
        Ok(inside) => !inside,
        Err(error) => {
            tracing::warn!(
                record = %root.to_hex(),
                %error,
                "room record delete: its private thread's audience not read"
            );
            false
        }
    }
}
