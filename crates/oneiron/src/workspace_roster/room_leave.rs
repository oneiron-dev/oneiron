//! The room leave door (FIX 3968).
//!
//! `rooms.leave` ends one person's live membership of a room as the bound
//! caller, through the same membership ledger as the HTTP member write's
//! `leave` action. A leave ends the person's current window and roles; the
//! participation it ended stays ended. Saving that rode on the live
//! participation stops with it, and a later `rooms.join` opens a new
//! membership rather than reviving the old one (ARCH-0052 #d5-save-grant,
//! #d5-bound-run).
//!
//! A leave is the person's own: filed by them or their principal, as a join
//! is ([`super::join_door::caller_stands_for_in_txn`], OF-531). Removing
//! someone else is the vault owner's, as an invitation is (OF-529).

use super::JoinSubject;
use crate::error::{ClaimError, Error, Result};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{EdgeActorClass, EntityId, Vault, WriteActor};

#[doc(hidden)]
pub use oneiron_verb_wire::workspace_roster::room_leave::RoomLeaveRequest;

#[doc(hidden)]
pub use oneiron_records::workspace_roster::room_leave::RoomLeaveOutcome;

impl Memory<'_> {
    /// Ends a person's current membership of a room for the bound actor, at
    /// the vault's recorded time, and returns the room's members after it.
    pub fn rooms_leave(&self, request: &RoomLeaveRequest) -> MemoryResult<RoomLeaveOutcome> {
        let vault = self.vault();
        let caller = self.write_actor();
        let member_ids = vault.try_with_write_txn_grouped(|txn| {
            let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            if !removes_member_in_txn(vault, txn, caller, request.person, now)? {
                return Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "a room leave is the person's own, or the vault owner's removal",
                    &["Leave as the person or their principal; the vault's owner removes anyone."],
                ));
            }
            vault.leave_member_in_txn(txn, request.room, request.person, caller, now)?;
            Ok::<_, MemoryError>(vault.members_in_txn(txn, request.room)?)
        })?;
        Ok(RoomLeaveOutcome { member_ids })
    }
}

/// Whether `caller` may end `person`'s membership of a room, judged at `now`
/// as this door judges it: the leave is the person's own, filed by them or
/// their principal, or `caller` is the vault's owner. A federation peer's
/// room body that drops a member is judged so too, as its sender's
/// (ROOM-BODY-REPLICA-SETTINGS).
pub(in crate::workspace_roster) fn removes_member_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: WriteActor,
    person: EntityId,
    now: u64,
) -> Result<bool> {
    let own = match super::join_door::caller_stands_for_in_txn(
        vault,
        txn,
        caller,
        &JoinSubject::Person(person),
        now,
    ) {
        Ok(_) => true,
        Err(Error::Claim(ClaimError::ActorLacksClaimAuthority { .. })) => false,
        Err(error) => return Err(error),
    };
    Ok(own || owner_removes_in_txn(vault, txn, caller))
}

/// Whether `caller` is the vault's owner: a Human actor the authority log
/// binds as owner, who removes anyone from a room.
fn owner_removes_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, caller: WriteActor) -> bool {
    caller.actor_class() == EdgeActorClass::Human
        && crate::memory::verify_owner_actor_binding_in_txn(vault, txn, caller.entity_ref()).is_ok()
}
