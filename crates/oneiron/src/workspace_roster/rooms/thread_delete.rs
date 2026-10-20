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

use super::audience::{names_actor_in, resolved_root_in, root_audience_in};
use super::audience_doors::{unknown_thread, vault_owner_or_admin_in};
use super::*;
use crate::deletion::DeleteReason;
use crate::error::RecordError;

/// `vault.rooms.thread_delete`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateThreadDeleteRequest {
    /// The private thread's root TURN, 32-hex.
    pub thread_ref: String,
}

/// What a private thread's delete did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateThreadDeleteReceipt {
    /// The thread's root TURN, 32-hex.
    pub thread_ref: String,
    /// Whether the root was there to delete.
    pub existed: bool,
    /// The delete's receipt, 32-hex, when it wrote one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_ref: Option<String>,
}

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
        let (carrier, known) = {
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
            (
                crate::conversation_dag::conversation_of(&vault.store, &txn, &root)?,
                inside || vault_owner_or_admin_in(vault, &txn, actor)?,
            )
        };
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
        })
    }
}
