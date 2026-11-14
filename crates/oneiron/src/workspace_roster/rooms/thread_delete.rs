//! Deleting a private thread (owner ruling 2026-10-20, FIX 6381, 6382): the
//! vault's Owner, or an Admin while the Owner's
//! `rooms.private_threads.admin_delete` is on, deletes a private thread by
//! its root, seated in the room or not.
//!
//! `vault.rooms.thread_delete` runs the room's own delete rail, a policy
//! delete of the root ([`Vault::delete_room_record`]): the root's own
//! MESSAGEs go first, then the root, every legal hold check of that rail as
//! it is, so a held record is kept and the delete refused. The authority
//! the rail meets for this one record is in
//! `conversation::deletion::private_thread`; a room role still deletes as
//! it did. A caller the rail refuses who is neither in the thread nor the
//! Owner or an Admin hears what an unknown thread hears.
//!
//! Check-in (ROLES-CHECKIN P2.5 2k5d; Engine ruling THREAD-DELETE-JUDGE =
//! B, 14 Nov 16:44) judges the vault-standing path only, and each receipt
//! records the decision: the vault's Owner deletes on their own proof, an
//! Admin's delete never asks, a Deputy's goes on their own judgment
//! (`sure`). A delete by a room role alone stays under the room's own
//! policy (FIX 6504), unjudged, as an agent's is. Nothing on this door
//! waits, so it takes no `check_in_ref`.

use super::audience::{names_actor_in, resolved_root_in, root_audience_in};
use super::audience_doors::{VaultStanding, unknown_thread, vault_standing_in};
use super::*;
use crate::check_in::{
    self, ActClass, CheckInDecision, CheckInScope, DoorAct, DoorCheckIn, RolePreset,
};
use crate::deletion::DeleteReason;
use crate::error::RecordError;

/// The saved verb a private thread's delete is judged under.
const THREAD_DELETE_VERB: &str = "vault.rooms.thread_delete";

#[doc(hidden)]
pub use oneiron_verb_wire::workspace_roster::rooms::thread_delete::{
    PrivateThreadDeleteReceipt, PrivateThreadDeleteRequest,
};

/// Whether `root` is a private thread's root of `room` in `txn`, read
/// strictly on base: a live TURN whose own binding names it and an
/// audience, held by one live conversation, carried by `room` or stamped
/// with `room` as its canonical room.
pub(crate) fn private_root_of_room_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    root: EntityId,
) -> Result<bool> {
    let Some(binding) = resolved_root_in(&vault.store.read(), txn, root)? else {
        return Ok(false);
    };
    Ok(binding.audience.is_some()
        && (binding.room == room
            || crate::conversation_dag::conversation_of(&vault.store, txn, &root)? == room))
}

impl Memory<'_> {
    /// Deletes a private thread by its root (FIX 6381, 6382): a policy
    /// delete of the root on the room's delete rail, its own messages
    /// first; legal holds keep what they name.
    pub fn rooms_thread_delete(
        &self,
        input: &PrivateThreadDeleteRequest,
    ) -> MemoryResult<PrivateThreadDeleteReceipt> {
        let root = EntityId::from_hex(&input.thread_ref)?;
        let vault = self.vault();
        let actor = self.actor();
        let (carrier, known, standing) = {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            let binding = resolved_root_in(&vault.store.read(), &txn, root)?
                .filter(|binding| binding.audience.is_some())
                .ok_or_else(unknown_thread)?;
            // A turn bound to one room deletes no other room's thread.
            if self
                .room_turn()
                .is_some_and(|turn| turn.room != binding.room)
            {
                return Err(unknown_thread());
            }
            let inside = match root_audience_in(vault, &txn, binding.room, root) {
                Ok(Some(folded)) => names_actor_in(vault, &txn, &folded.current(), actor)?,
                Ok(None) | Err(Error::EntityNotFound) => return Err(unknown_thread()),
                Err(error) => return Err(error.into()),
            };
            let standing = vault_standing_in(vault, &txn, actor)?;
            (
                crate::conversation_dag::conversation_of(&vault.store, &txn, &root)?,
                inside || standing.is_some(),
                standing,
            )
        };
        let check_in = self.thread_delete_check_in(root, standing)?;
        let outcome = match vault.delete_room_record(
            carrier,
            root,
            crate::WriteActor::new(actor, self.actor_class()),
            DeleteReason::PolicyDelete,
        ) {
            Ok(outcome) => outcome,
            Err(Error::Record(RecordError::ConversationDenied)) if !known => {
                return Err(unknown_thread());
            }
            Err(error) => return Err(error.into()),
        };
        Ok(PrivateThreadDeleteReceipt {
            thread_ref: root.to_hex(),
            existed: outcome.existed,
            receipt_ref: outcome.receipt_id.map(|id| id.to_hex()),
            check_in,
        })
    }

    /// The check-in decision of this actor's delete of the private thread
    /// rooted at `root`, `standing` their vault standing read with the
    /// thread (module docs). The rail meets a vault standing only for a
    /// human (conversation::deletion::private_thread), so an agent's or a
    /// pen's delete records none; so does a room role's alone. The Owner's
    /// goes on their own proof. An Admin or a Deputy is judged under their
    /// membership role in a writer of its own before the rail, which reads
    /// their standing again: one whose admin grant is gone by then records
    /// none.
    fn thread_delete_check_in(
        &self,
        root: EntityId,
        standing: Option<VaultStanding>,
    ) -> MemoryResult<Option<CheckInDecision>> {
        if self.actor_class() != crate::EdgeActorClass::Human {
            return Ok(None);
        }
        match standing {
            None => Ok(None),
            Some(VaultStanding::Owner) => {
                Ok(Some(check_in::owner_own_proof_decision(ActClass::Delete)))
            }
            Some(VaultStanding::Admin) => {
                let vault = self.vault();
                let actor = self.actor();
                Ok(vault.try_with_write_txn_grouped(|txn| {
                    admin_thread_delete_check_in_in_txn(vault, txn, actor, root)
                })?)
            }
        }
    }
}

/// `actor`'s delete of the private thread rooted at `root` as an Admin or a
/// Deputy, judged in `txn`, the judge's writer, under their membership role
/// (ARCH-0082 #act-table "Delete items": Admin go, Deputy unsure): an
/// Admin's never asks, a Deputy's goes as `sure`. The digest binds the
/// root's policy delete. `None` for one with no admin grant on the shared
/// vault now.
///
/// # Errors
///
/// `InvariantViolation` if the judge would make this delete wait, which no
/// admin role's cell does; as [`check_in::person_door_check_in_in_txn`].
fn admin_thread_delete_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    root: EntityId,
) -> Result<Option<CheckInDecision>> {
    let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
    let Some(person) = crate::workspace_roster::person_of_actor_in_txn(vault, txn, actor, at)?
    else {
        return Ok(None);
    };
    let Some(creation) = vault.shared_vault_creation_in_txn(txn)? else {
        return Ok(None);
    };
    let Some((grant, role)) = vault.member_grant_in_txn(txn, creation.vault_id, person)? else {
        return Ok(None);
    };
    if !role.is_admin() {
        return Ok(None);
    }
    let act = DoorAct {
        person,
        role: RolePreset::of_grant_role(role),
        grant,
        verb: THREAD_DELETE_VERB,
        act: ActClass::Delete,
        scope: CheckInScope::default(),
        effect_digest: check_in::record_delete_effect_digest(&root, DeleteReason::PolicyDelete),
    };
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    match check_in::person_door_check_in_in_txn(vault, txn, &act, None, now)? {
        DoorCheckIn::Go(decision) => Ok(Some(decision)),
        DoorCheckIn::Wait(_) => Err(Error::InvariantViolation(
            "a private thread's delete by an Admin or a Deputy never waits",
        )),
    }
}
