//! The doors that edit a private thread's audience (FIX 5545): an add and a
//! remove, each one audience edit TURN of the thread, written in the door's
//! one write ([`super::audience_events`]).
//!
//! # Who edits
//!
//! The vault's Owner or an Admin, and anyone in the thread's audience now who
//! is still one of its room's members, a pen through its PERSON. A pen is
//! also its PERSON's will within its Grant, so it edits where its PERSON
//! does. Anyone else is refused as an unknown thread is, so the door says
//! nothing of a thread they are off; the Owner and an Admin, who may know a
//! private thread exists, hear why.
//!
//! # Whom
//!
//! An add names a live PERSON or AGENT_DEF among the room's members now, by
//! the rules a new thread's audience meets, its opener aside; the Owner or an
//! Admin adding themselves may be off the room. Adding someone already in
//! the audience records the history chosen now. A remove names anyone, a
//! member who left too, and may leave the audience empty. No door turns a
//! public thread private.

use super::audience::{ThreadBinding, names_actor_in, root_audience_in, thread_binding};
use super::audience_events::{AudienceEvent, AudienceOp, ThreadAudienceHistory, event_body};
use super::*;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// `vault.rooms.thread_audience.add`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadAudienceAddRequest {
    /// The private thread's root TURN, 32-hex.
    pub thread_ref: String,
    /// The PERSON or AGENT_DEF added, 32-hex.
    pub person_ref: String,
    /// What the added person reads: the whole thread, or its turns from this
    /// add on.
    pub history: ThreadAudienceHistory,
}

/// `vault.rooms.thread_audience.remove`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadAudienceRemoveRequest {
    /// The private thread's root TURN, 32-hex.
    pub thread_ref: String,
    /// The PERSON or AGENT_DEF removed, 32-hex.
    pub person_ref: String,
}

/// What an audience edit wrote: its thread's root and the edit's own TURN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadAudienceReceipt {
    pub thread_ref: String,
    pub event_ref: String,
}

/// Whether `actor` is the vault's Owner or an Admin in `txn`: a live PERSON
/// among the vault's owners, or holding a live Owner or Admin grant over the
/// shared vault, or a pen anchored to one.
pub(super) fn vault_owner_or_admin_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> Result<bool> {
    let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
    let Some(person) = crate::workspace_roster::person_of_actor_in_txn(vault, txn, actor, at)?
    else {
        return Ok(false);
    };
    if live_entity_row_in_txn(&vault.store, txn, &person)?.live_type() != Some(ENTITY_TYPE_PERSON) {
        return Ok(false);
    }
    if crate::policy_model::owners_in_txn(vault, txn)?.contains(&person) {
        return Ok(true);
    }
    let Some(creation) = vault.shared_vault_creation_in_txn(txn)? else {
        return Ok(false);
    };
    Ok(matches!(
        vault.membership_standing_in_txn(txn, creation.vault_id, &person)?,
        Some(crate::federation::MembershipStanding::Member { role, .. }) if role.is_admin()
    ))
}

/// The refusal for a thread the caller may not edit, or that is no private
/// thread: the one an unknown thread meets.
fn unknown_thread() -> MemoryError {
    MemoryError::not_found("no private thread by that ref")
}

impl Memory<'_> {
    /// Adds a person to a private thread's audience (FIX 5545), sharing the
    /// whole thread or its turns from this add on: one audience edit TURN of
    /// the thread.
    pub fn rooms_thread_audience_add(
        &self,
        input: &ThreadAudienceAddRequest,
    ) -> MemoryResult<ThreadAudienceReceipt> {
        self.edit_thread_audience(&input.thread_ref, &input.person_ref, Some(input.history))
    }

    /// Removes a person from a private thread's audience (FIX 5545): every
    /// read of theirs ends with this edit, the thread's earlier turns too.
    pub fn rooms_thread_audience_remove(
        &self,
        input: &ThreadAudienceRemoveRequest,
    ) -> MemoryResult<ThreadAudienceReceipt> {
        self.edit_thread_audience(&input.thread_ref, &input.person_ref, None)
    }

    /// The write both doors make, in one transaction: the thread, the
    /// caller's standing, the target and the edit's TURN. `history` is an
    /// add's; `None` removes.
    fn edit_thread_audience(
        &self,
        thread_ref: &str,
        person_ref: &str,
        history: Option<ThreadAudienceHistory>,
    ) -> MemoryResult<ThreadAudienceReceipt> {
        let root = EntityId::from_hex(thread_ref)?;
        let person = EntityId::from_hex(person_ref)?;
        let actor = self.actor();
        self.with_verified_actor_write_txn(|txn| {
            let vault = self.vault();
            // The root, read strictly: a live TURN whose own binding names it.
            let binding = match live_entity_row_in_txn(&vault.store, txn, &root)? {
                LiveEntityRow::Live {
                    entity_type: ENTITY_TYPE_TURN,
                    body,
                } => thread_binding(&body)?.filter(|binding| binding.root == root),
                _ => None,
            }
            .ok_or_else(unknown_thread)?;
            let room = binding.room;
            // A turn bound to one room edits no other room's thread.
            if self.room_turn().is_some_and(|turn| turn.room != room) {
                return Err(unknown_thread());
            }
            let privileged = vault_owner_or_admin_in(vault, txn, actor)?;
            let folded = match root_audience_in(vault, txn, room, root) {
                Ok(Some(folded)) => folded,
                Ok(None) if privileged => {
                    return Err(MemoryError::bad_request(
                        "a public thread has no audience to edit",
                    ));
                }
                Ok(None) | Err(Error::EntityNotFound) => return Err(unknown_thread()),
                Err(error) => return Err(error.into()),
            };
            let members: BTreeSet<_> = vault
                .room_audience_members_in_txn(txn, room)?
                .into_iter()
                .collect();
            if !privileged
                && !(names_actor_in(vault, txn, &folded.current(), actor)?
                    && names_actor_in(vault, txn, &members, actor)?)
            {
                return Err(unknown_thread());
            }
            if history.is_some() {
                let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
                let own = privileged
                    && (person == actor
                        || crate::workspace_roster::person_of_actor_in_txn(vault, txn, actor, at)?
                            == Some(person));
                if !matches!(
                    live_entity_row_in_txn(&vault.store, txn, &person)?.live_type(),
                    Some(ENTITY_TYPE_PERSON | ENTITY_TYPE_AGENT_DEF)
                ) || (!own && !names_actor_in(vault, txn, &members, person)?)
                {
                    return Err(MemoryError::bad_request(
                        "an added person must be a live PERSON or AGENT_DEF among the room's members",
                    ));
                }
            }
            let event = AudienceEvent {
                root,
                person,
                by: actor,
                op: if history.is_some() {
                    AudienceOp::Add
                } else {
                    AudienceOp::Remove
                },
                history,
            };
            let reply = ThreadBinding {
                root,
                room,
                anchor: binding.anchor,
                audience: None,
            };
            let id = vault.store.clock.entity_id()?;
            crate::conversation_dag::put_thread_event_in_txn(
                vault,
                txn,
                id,
                room,
                root,
                &event_body(&reply, &event)?,
            )?;
            Ok(ThreadAudienceReceipt {
                thread_ref: root.to_hex(),
                event_ref: id.to_hex(),
            })
        })
    }
}
