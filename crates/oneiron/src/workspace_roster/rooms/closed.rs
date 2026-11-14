//! Whether a room is closed (ARCH-0082 #closed-room; Engine ruling P26-SHAPE
//! Q5 = A): every add to a closed room asks the room's owner, whoever adds.
//! Only a person who is an owner of the room closes or opens it
//! ([`crate::conversation::person_role_in`]), never an agent. The bit lives
//! on the room body and changes only through this door
//! ([`crate::conversation::CLOSED_UPDATES`]). A project's home room is not
//! closed here: its project's leader and board admit people to it.
use super::*;
use crate::EdgeActorClass;
use crate::conversation::{CLOSED_UPDATES, ConversationBody, RoomRole};
use crate::error::{ClaimError, RecordError};
use crate::write_envelope::WriteActor;

#[doc(hidden)]
pub use oneiron_verb_wire::workspace_roster::rooms::closed::RoomClosedSet;

const CLOSED_BY_PERSON: &str = "a person closes or opens a room, never an agent";
const NOT_ROOM_OWNER: &str = "only an owner of the room closes or opens it";
const HOME_ROOM: &str = "a project's home room is not closed or opened here";
const HOME_ROOM_HINT: &str =
    "Close an ordinary room; a home room admits people through its project's leader and board.";

/// A person closes or opens a room, never an agent: checked before
/// anything is read.
fn require_person(caller: WriteActor) -> MemoryResult<()> {
    if caller.actor_class() != EdgeActorClass::Human {
        return Err(lacks(CLOSED_BY_PERSON));
    }
    Ok(())
}

/// The stored body of `room` when the person `caller` may close or open it,
/// read in `txn`: an owner of the room, in an ordinary room, never a
/// project's home room.
fn closed_setter_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    caller: WriteActor,
) -> MemoryResult<ConversationBody> {
    if project_room_of(vault, txn, room)?.is_some() {
        return Err(MemoryError::bad_request_with(HOME_ROOM, &[HOME_ROOM_HINT]));
    }
    let body = crate::conversation::body_in(vault, txn, room)?;
    match crate::conversation::person_role_in(vault, txn, room, caller.entity_ref(), true) {
        Ok(RoomRole::Owner) => Ok(body),
        Ok(_) | Err(Error::Record(RecordError::ConversationDenied)) => Err(lacks(NOT_ROOM_OWNER)),
        Err(error) => Err(error.into()),
    }
}

fn lacks(reason: &'static str) -> MemoryError {
    Error::Claim(ClaimError::ActorLacksClaimAuthority { reason }).into()
}

impl Memory<'_> {
    /// `vault.rooms.closed.set`: closes or opens `room_ref`. Only a person
    /// who is an owner of the room sets it ([`closed_setter_in`]); an agent
    /// never does. Answers the stored setting; an unchanged call writes
    /// nothing.
    pub fn rooms_closed_set(&self, input: &RoomClosedSet) -> MemoryResult<RoomClosedSet> {
        let vault = self.vault();
        let caller = self.write_actor();
        require_person(caller)?;
        let room = input.room_ref;
        let (closed, changed) = vault.try_with_write_txn_grouped(|txn| {
            vault.verify_write_actor_in_txn(txn, &caller)?;
            let mut body = closed_setter_in(vault, txn, room, caller)?;
            if body.closed == input.closed {
                return Ok::<_, MemoryError>((body.closed, false));
            }
            body.closed = input.closed;
            CLOSED_UPDATES.put(&vault.store, txn, &room, &[1])?;
            super::pins::put_room_body_in(vault, txn, room, &body.to_bytes()?)?;
            CLOSED_UPDATES.delete(&vault.store, txn, &room)?;
            Ok((body.closed, true))
        })?;
        #[cfg(feature = "sync")]
        if changed {
            vault.refresh_room_cell_in_live_window(room, None);
        }
        #[cfg(not(feature = "sync"))]
        let _ = changed;
        Ok(RoomClosedSet {
            room_ref: room,
            closed,
        })
    }

    /// `vault.rooms.closed.set`'s admission, read only, for `can({verb})`:
    /// a person, the writer's own standing, then [`closed_setter_in`]. The
    /// door checks them again in its own write transaction.
    pub(crate) fn rooms_closed_set_admission(&self, input: &RoomClosedSet) -> MemoryResult<()> {
        let vault = self.vault();
        let caller = self.write_actor();
        require_person(caller)?;
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        vault.verify_write_actor_in_txn(&txn, &caller)?;
        closed_setter_in(vault, &txn, input.room_ref, caller)?;
        Ok(())
    }
}
