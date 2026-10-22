//! A thread's own reader and ceiling (OF-529, FIX 2951): who reads one
//! thread of a room, and the ceiling that thread puts on its reader, over the
//! room's roster.

use super::{room_clearance_in, room_reader_in, room_roster_in};
use crate::claim::RoomTurnCeiling;
use crate::federation::Scope;
use crate::{EntityId, Vault};

/// Whether `caller` reads thread `thread` of `room` as `txn` reads it
/// (OF-529): a reader of the room ([`room_reader_in`]), or an AGENT_DEF
/// standing on an OF-531 Ready join for that thread itself. A thread's join
/// opens that thread's reads alone, never the room's or another thread's,
/// and takes no seat. A private thread (FIX 2951) is read by its audience
/// alone, before any of these, and one hidden from `caller` reads as a
/// missing one. Last, the vault's Owner or an Admin in a private thread's
/// audience reads that thread with no standing in the room (FIX 5638).
pub(crate) fn thread_reader_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    thread: EntityId,
    members: &[EntityId],
    caller: EntityId,
) -> crate::Result<bool> {
    match crate::workspace_roster::thread_audience_allows_in(vault, txn, room, thread, caller) {
        Ok(true) => {}
        Ok(false) | Err(crate::Error::EntityNotFound) => return Ok(false),
        Err(error) => return Err(error),
    }
    if room_reader_in(vault, txn, room, members, caller)? {
        return Ok(true);
    }
    if vault.get_entity_type_in_txn(txn, &caller)? == Some(crate::registry::ENTITY_TYPE_AGENT_DEF) {
        let agent = crate::workspace_roster::JoinSubject::Agent(caller);
        match crate::workspace_roster::require_join_for_branch_in_txn(
            vault,
            txn,
            room,
            Some(thread),
            &agent,
            None,
        ) {
            Ok(_) => return Ok(true),
            Err(crate::Error::Claim(crate::error::ClaimError::ActorLacksClaimAuthority {
                ..
            })) => {}
            Err(error) => return Err(error),
        }
    }
    crate::workspace_roster::privileged_private_thread_reader_in(vault, txn, room, thread, caller)
}

/// [`room_ceiling_in`](super::room_ceiling_in) for a reader of thread `thread` of `room`
/// ([`thread_reader_in`]): the same terms, audience and peer reads over the
/// room's roster in this snapshot, which a thread's reader never joins. A
/// private thread's (FIX 2951) are over the members in its audience alone;
/// one whose audience holds no member now, read by the vault's Owner or an
/// Admin in it off the room (FIX 6267), is bound to that caller alone: its
/// worlds and clearance, and it as the audience. One whose audience still
/// holds members, read so, meets that caller's own clearance too
/// ([`off_room_reader_clearance_in`], FIX 6497). `None` when `caller` does
/// not read the thread here. Held, as the room's.
pub(crate) fn thread_ceiling_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    thread: EntityId,
    caller: EntityId,
) -> crate::Result<Option<RoomTurnCeiling>> {
    let Some(members) = room_roster_in(vault, txn, room)? else {
        return Ok(None);
    };
    if !thread_reader_in(vault, txn, room, thread, &members, caller)? {
        return Ok(None);
    }
    let mut members =
        crate::workspace_roster::thread_members_in(vault, txn, room, thread, &members)?;
    if members.is_empty()
        && crate::workspace_roster::privileged_private_thread_reader_in(
            vault, txn, room, thread, caller,
        )?
    {
        members.push(caller);
    }
    let own = off_room_reader_clearance_in(vault, txn, room, thread, &members, caller)?;
    let mut ceiling =
        super::ceiling::room_turn_ceiling_in(vault, txn, room, caller, &members, own.as_ref())?;
    ceiling.branch = Some(thread);
    Ok(Some(ceiling))
}

/// What the vault's Owner or an Admin reading a private thread off the room
/// brings to its ceiling while the audience still holds room members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OffRoomReaderClearance {
    /// Its own contact clearance meets into the P7 terms beside the members';
    /// it joins no roster, world, peer read or audience.
    MeetOwn,
}

/// CALLS `FIX 6497 off-room privileged reader clearance`: the one value
/// [`off_room_reader_clearance_in`] reads, for the constructor and the
/// per-row refresh alike.
const OFF_ROOM_PRIVILEGED_READER_CLEARANCE: OffRoomReaderClearance =
    OffRoomReaderClearance::MeetOwn;

/// The clearance `caller` brings to private thread `thread` of `room` beside
/// `members`, the room's members in its audience now (FIX 6497): when they
/// are not empty, `caller` is none of them (a pen through its PERSON), and
/// it is the vault's Owner or an Admin in that audience reading off the room
/// ([`crate::workspace_roster::privileged_private_thread_reader_in`]), its
/// own clearance as `txn` reads it. `None` otherwise: a public thread, a
/// member's own read, the empty-audience case (FIX 6336) that binds the
/// caller as a member instead. The vault owner and the vault's own agents
/// bring no clearance, so for them this is `None` too.
pub(crate) fn off_room_reader_clearance_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    thread: EntityId,
    members: &[EntityId],
    caller: EntityId,
) -> crate::Result<Option<Scope>> {
    if members.is_empty()
        || members.contains(&caller)
        || !crate::workspace_roster::privileged_private_thread_reader_in(
            vault, txn, room, thread, caller,
        )?
    {
        return Ok(None);
    }
    let named: std::collections::BTreeSet<_> = members.iter().copied().collect();
    if crate::workspace_roster::names_actor_in(vault, txn, &named, caller)? {
        return Ok(None);
    }
    match OFF_ROOM_PRIVILEGED_READER_CLEARANCE {
        OffRoomReaderClearance::MeetOwn => room_clearance_in(vault, txn, &[caller]),
    }
}
