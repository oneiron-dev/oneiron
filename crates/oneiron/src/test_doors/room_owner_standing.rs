//! Doors for `tests/room_role_deleted_person.rs` (FIX
//! ROOM-ROLE-UNROOTED-EMBEDDED-OWNER-LIVENESS): a room's owners and a
//! PERSON's room role as the callers that skip the role door's write-actor
//! check read them (a closed room's check-in rung, a federation peer's room
//! body), each in one read transaction. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use crate::conversation::RoomRole;
use crate::error::Result;
use crate::{EntityId, Vault};

/// The PERSONs who own `room` ([`crate::conversation::room_owners_in`]).
pub fn room_owners(vault: &Vault, room: EntityId) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    crate::conversation::room_owners_in(vault, &txn, room)
}

/// The role PERSON `person` holds in `room`, acting as a human when `human`
/// ([`crate::conversation::person_role_in`]).
pub fn person_room_role(
    vault: &Vault,
    room: EntityId,
    person: EntityId,
    human: bool,
) -> Result<RoomRole> {
    let txn = vault.store.env.read_txn()?;
    crate::conversation::person_role_in(vault, &txn, room, person, human)
}

/// The embedded owner's actor id, whether or not its PERSON row was written.
pub fn embedded_owner_actor_id() -> Result<EntityId> {
    crate::vault::embedded_owner_actor_id()
}
