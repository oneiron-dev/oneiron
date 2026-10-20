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
//! member who left too, and may leave the audience empty; one this vault
//! erased, or whom the thread's edits forgot, it names by the root's
//! stand-in for them (FIX 5640). No door turns a public thread private.
//!
//! # Walking in
//!
//! Owner ruling 2026-10-20 (FIX 6381, 6383, 6384). The Owner or an Admin,
//! as a person, adding themselves walks in: from now on, whatever history
//! the call asked for. An Admin walks in only while the Owner's
//! `rooms.private_threads.admin_walk_in` is on. Every member is told, and
//! the walker shows in the thread's member list
//! ([`super::audience_notices`]). An agent never walks in, a pen of the
//! Owner or an Admin included: it asks to join ([`super::thread_join`]).
//! Anyone adding themselves when already in, a member or an agent alike,
//! changes nothing, whatever history they ask: their own cut never moves
//! (Engine ruling 10-20 17:3x). A member inside the thread adding anyone
//! else keeps their own pick. From outside the thread an Admin's add is
//! from now on, and changes nothing for someone already in; the Owner's add
//! from now on moves the cut of someone already in forward, and the
//! Owner's add with full history opens the thread's full history to the
//! person added ([`super::audience_history`]), logged, and its members
//! told.
//!
//! # Off record
//!
//! An audience edit is the thread's structure, not its talk (FIX 5643): it
//! writes base while the room is off record, as a room handle's binding and
//! a room claim do. Audience changes persist even while talk is off record;
//! they are not saved or discarded with the transcript.

use super::audience::{ThreadBinding, names_actor_in, root_audience_in, thread_binding};
use super::audience_events::{
    AudienceEvent, AudienceOp, AudiencePerson, FoldedAudience, ThreadAudienceHistory, event_body,
    removed_person_in,
};
use super::audience_notices::{ThreadNotice, tell_thread_members};
use super::*;
use crate::EdgeActorClass;
use crate::memory::MEMORY_CODE_INVALID_STATE;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::settings::room_threads::{
    ROOM_THREADS_ADMIN_WALK_IN_KEY, room_thread_admin_settings_in_txn,
};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::workspace_roster::RosterActor;

/// The rule an agent's self-add into a private thread it is not in meets
/// (FIX 6384), as its refusal names it.
const AGENT_THREAD_WALK_IN_FORBIDDEN: &str = "AGENT_THREAD_WALK_IN_FORBIDDEN";

/// `vault.rooms.thread_audience.add`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadAudienceAddRequest {
    /// The private thread's root TURN, 32-hex.
    pub thread_ref: String,
    /// The PERSON or AGENT_DEF added, 32-hex.
    pub person_ref: String,
    /// What the added person reads: the whole thread, or its turns from this
    /// add on. A walk-in reads from now on whatever this asks (FIX 6381), and
    /// so does an Admin's add from outside the thread; a self re-add, and an
    /// Admin's outside add for someone already in, change nothing.
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
    /// What the person the edit names reads of the thread after it, the
    /// history that applied (FIX 6381): `from_now` for a walk-in that
    /// entered whatever its call asked, as before for one already in.
    /// Absent on a remove.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<ThreadAudienceHistory>,
}

/// A private thread as an edit door reads it in its write (FIX 5545): its
/// binding, its audience and its room's members now, and the caller's
/// standing.
pub(super) struct EditedThread {
    pub(super) binding: ThreadBinding,
    pub(super) folded: FoldedAudience,
    pub(super) members: BTreeSet<EntityId>,
    /// The caller is the vault's Owner or an Admin, or a pen anchored to one.
    pub(super) privileged: bool,
    /// The caller is in the audience now, a pen through its PERSON.
    pub(super) inside: bool,
}

/// Whether `actor` is the vault's Owner or an Admin in `txn`: a live PERSON
/// among the vault's owners, or holding a live Owner or Admin grant over the
/// shared vault, or a pen anchored to one.
pub(super) fn vault_owner_or_admin_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> Result<bool> {
    Ok(vault_standing_in(vault, txn, actor)?.is_some())
}

/// What `actor` is to the vault, through the PERSON a pen is anchored to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultStanding {
    /// A live PERSON among the vault's owners.
    Owner,
    /// A live PERSON holding an Admin grant over the shared vault, and no
    /// owner.
    Admin,
}

/// `actor`'s [`VaultStanding`] in `txn`, a pen through its PERSON; `None`
/// for anyone neither the vault's Owner nor an Admin.
pub(crate) fn vault_standing_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> Result<Option<VaultStanding>> {
    let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
    let Some(person) = crate::workspace_roster::person_of_actor_in_txn(vault, txn, actor, at)?
    else {
        return Ok(None);
    };
    if live_entity_row_in_txn(&vault.store, txn, &person)?.live_type() != Some(ENTITY_TYPE_PERSON) {
        return Ok(None);
    }
    if crate::policy_model::owners_in_txn(vault, txn)?.contains(&person) {
        return Ok(Some(VaultStanding::Owner));
    }
    let Some(creation) = vault.shared_vault_creation_in_txn(txn)? else {
        return Ok(None);
    };
    Ok(matches!(
        vault.membership_standing_in_txn(txn, creation.vault_id, &person)?,
        Some(crate::federation::MembershipStanding::Member { role, .. }) if role.is_admin()
    )
    .then_some(VaultStanding::Admin))
}

/// The refusal for a thread the caller may not edit, or that is no private
/// thread: the one an unknown thread meets.
pub(super) fn unknown_thread() -> MemoryError {
    MemoryError::not_found("no private thread by that ref")
}

/// The refusal for an agent's self-add into a private thread it is not in
/// (FIX 6384), a pen of the Owner or an Admin included: it asks to join.
fn agent_walk_in_forbidden() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!(
            "{AGENT_THREAD_WALK_IN_FORBIDDEN}: agents may request to join a private thread; they cannot walk in"
        ),
        &["Ask the thread's members to add the agent, or have it request to join."],
    )
}

/// The refusal for an Admin's walk-in while the Owner has turned it off
/// (FIX 6382), naming the setting.
fn admin_walk_in_off() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!(
            "the Owner's setting {ROOM_THREADS_ADMIN_WALK_IN_KEY} is off: an Admin may not walk into a private thread"
        ),
        &["Ask the thread's members to add you, or the Owner to turn the setting on."],
    )
}

/// Writes `event` as a new TURN of the thread `binding` names, in `txn`:
/// carried by its room, with an `About` edge to its root. Answers its id.
pub(super) fn put_audience_event_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding: &ThreadBinding,
    event: &AudienceEvent,
) -> Result<EntityId> {
    let reply = ThreadBinding {
        root: binding.root,
        room: binding.room,
        anchor: binding.anchor,
        audience: None,
    };
    let id = vault.store.clock.entity_id()?;
    crate::conversation_dag::put_thread_event_in_txn(
        vault,
        txn,
        id,
        binding.room,
        binding.root,
        &event_body(&reply, event)?,
    )?;
    Ok(id)
}

/// The receipt of the edit `id` of the thread `binding` names, read in its
/// write after it: what `person`, the person an add names, reads now. A
/// fold that does not read leaves the history out, logged; it never fails
/// the edit.
pub(super) fn receipt_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding: &ThreadBinding,
    id: EntityId,
    person: Option<EntityId>,
) -> ThreadAudienceReceipt {
    let history =
        person.and_then(
            |person| match root_audience_in(vault, txn, binding.room, binding.root) {
                Ok(folded) => folded.and_then(|folded| folded.history_of(person)),
                Err(error) => {
                    tracing::warn!(
                        thread = %binding.root.to_hex(),
                        event = %id.to_hex(),
                        %error,
                        "thread audience receipt: history not read"
                    );
                    None
                }
            },
        );
    ThreadAudienceReceipt {
        thread_ref: binding.root.to_hex(),
        event_ref: id.to_hex(),
        history,
    }
}

impl Memory<'_> {
    /// Adds a person to a private thread's audience (FIX 5545), sharing the
    /// whole thread or its turns from this add on: one audience edit TURN of
    /// the thread. The Owner or an Admin adding themselves walks in from now
    /// on (FIX 6381); an agent never walks in (FIX 6384). Audience changes
    /// persist even while talk is off record; they are not saved or
    /// discarded with the transcript (FIX 5643).
    pub fn rooms_thread_audience_add(
        &self,
        input: &ThreadAudienceAddRequest,
    ) -> MemoryResult<ThreadAudienceReceipt> {
        self.edit_thread_audience(&input.thread_ref, &input.person_ref, Some(input.history))
    }

    /// Removes a person from a private thread's audience (FIX 5545): every
    /// read of theirs ends with this edit, the thread's earlier turns too.
    /// Audience changes persist even while talk is off record; they are not
    /// saved or discarded with the transcript (FIX 5643).
    pub fn rooms_thread_audience_remove(
        &self,
        input: &ThreadAudienceRemoveRequest,
    ) -> MemoryResult<ThreadAudienceReceipt> {
        self.edit_thread_audience(&input.thread_ref, &input.person_ref, None)
    }

    /// The private thread rooted at `root` as an edit door reads it in its
    /// write `txn`, read strictly: a live TURN whose own binding names it, of
    /// the room a room-bound turn is bound to. Anyone not the Owner or an
    /// Admin, and not in its audience and its room now, is refused as an
    /// unknown thread is.
    pub(super) fn edited_thread_in(
        &self,
        txn: &heed::RoTxn<'_>,
        root: EntityId,
    ) -> MemoryResult<EditedThread> {
        let vault = self.vault();
        let actor = self.actor();
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
        let inside = names_actor_in(vault, txn, &folded.current(), actor)?;
        if !privileged && !(inside && names_actor_in(vault, txn, &members, actor)?) {
            return Err(unknown_thread());
        }
        Ok(EditedThread {
            binding,
            folded,
            members,
            privileged,
            inside,
        })
    }

    /// The edit an add of `person` to `thread` asking `history` writes. A
    /// self re-add, anyone adding themselves or their PERSON already in the
    /// audience, member or agent alike, is a walk-in that folds as nothing,
    /// whatever `history` asks: no one's own cut moves (Engine ruling 10-20
    /// 17:3x (a)). Else a walk-in for the Owner or an Admin adding
    /// themselves, as a person (FIX 6381), refused for an Admin while the
    /// Owner's setting is off (FIX 6382). From outside the thread an
    /// Admin's add is from now on, and for someone already in a walk-in
    /// that changes nothing, `from_now` included (17:3x (b)); the Owner's
    /// with full history is an opened history (FIX 6383), and the Owner's
    /// from now on an add that moves the cut of someone already in forward.
    /// Else an add with the caller's pick. An agent adding itself, or its
    /// PERSON, into a thread they are not in is refused (FIX 6384).
    fn added_event_in(
        &self,
        txn: &heed::RoTxn<'_>,
        thread: &EditedThread,
        person: EntityId,
        history: ThreadAudienceHistory,
    ) -> MemoryResult<AudienceEvent> {
        let vault = self.vault();
        let actor = self.actor();
        let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
        let own = person == actor
            || crate::workspace_roster::person_of_actor_in_txn(vault, txn, actor, at)?
                == Some(person);
        let entering = !thread.folded.current().contains(&person);
        // The verified class of this write's actor, never a caller's flag.
        let human = self.actor_class() == EdgeActorClass::Human;
        if own && entering && !human {
            return Err(agent_walk_in_forbidden());
        }
        if !matches!(
            live_entity_row_in_txn(&vault.store, txn, &person)?.live_type(),
            Some(ENTITY_TYPE_PERSON | ENTITY_TYPE_AGENT_DEF)
        ) || (!(own && thread.privileged)
            && !names_actor_in(vault, txn, &thread.members, person)?)
        {
            return Err(MemoryError::bad_request(
                "an added person must be a live PERSON or AGENT_DEF among the room's members",
            ));
        }
        let walk_in = own && thread.privileged && human;
        let outside = thread.privileged && !thread.inside && !own;
        // The strict live Owner as a person; read only where it decides.
        let owner = (walk_in || outside)
            && human
            && crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &actor)?;
        let (op, history) = if own && !entering {
            // A self re-add never moves the caller's own cut: a walk-in
            // folds as nothing for someone already in.
            (AudienceOp::WalkIn, None)
        } else if walk_in {
            if !owner && !room_thread_admin_settings_in_txn(vault, txn)?.admin_walk_in {
                return Err(admin_walk_in_off());
            }
            (AudienceOp::WalkIn, None)
        } else if outside {
            if owner && history == ThreadAudienceHistory::Full {
                (AudienceOp::OpenFullHistory, None)
            } else if !owner && !entering {
                // An Admin's outside add changes nothing for someone
                // already in, either way: a walk-in folds as nothing.
                (AudienceOp::WalkIn, None)
            } else {
                (AudienceOp::Add, Some(ThreadAudienceHistory::FromNow))
            }
        } else {
            (AudienceOp::Add, Some(history))
        };
        Ok(AudienceEvent {
            root: thread.binding.root,
            person: AudiencePerson::Live(person),
            by: RosterActor::Actor(actor),
            op,
            history,
            request: None,
        })
    }

    /// The write both doors make, in one transaction: the thread, the
    /// caller's standing, the target and the edit's TURN. `history` is an
    /// add's; `None` removes. A walk-in that entered, and the Owner's add
    /// with full history, tell the thread's members once it committed.
    fn edit_thread_audience(
        &self,
        thread_ref: &str,
        person_ref: &str,
        history: Option<ThreadAudienceHistory>,
    ) -> MemoryResult<ThreadAudienceReceipt> {
        let root = EntityId::from_hex(thread_ref)?;
        let person = EntityId::from_hex(person_ref)?;
        let actor = self.actor();
        let (receipt, notice) = self.with_verified_actor_write_txn(|txn| {
            let vault = self.vault();
            let thread = self.edited_thread_in(txn, root)?;
            let event = match history {
                Some(history) => self.added_event_in(txn, &thread, person, history)?,
                None => AudienceEvent {
                    root,
                    person: removed_person_in(
                        vault,
                        txn,
                        &thread.folded,
                        thread.binding.room,
                        root,
                        person,
                    )?,
                    by: RosterActor::Actor(actor),
                    op: AudienceOp::Remove,
                    history: None,
                    request: None,
                },
            };
            let id = put_audience_event_in(vault, txn, &thread.binding, &event)?;
            let notice = match event.op {
                AudienceOp::WalkIn if !thread.folded.current().contains(&person) => {
                    Some(ThreadNotice::WalkIn { event: id })
                }
                AudienceOp::OpenFullHistory => {
                    Some(ThreadNotice::OwnerAddedFullHistory { event: id, person })
                }
                _ => None,
            };
            let named = (event.op != AudienceOp::Remove).then_some(person);
            Ok((receipt_in(vault, txn, &thread.binding, id, named), notice))
        })?;
        if let Some(notice) = notice {
            if let ThreadNotice::OwnerAddedFullHistory { event, .. } = notice {
                tracing::info!(
                    thread = %root.to_hex(),
                    person = %person.to_hex(),
                    owner = %actor.to_hex(),
                    event = %event.to_hex(),
                    "the Owner added a person to a private thread with its full history"
                );
            }
            tell_thread_members(self.vault(), root, actor, notice);
        }
        Ok(receipt)
    }
}
