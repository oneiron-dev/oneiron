//! A thread's own reader and ceiling (OF-529, FIX 2951): who reads one
//! thread of a room, and the ceiling that thread puts on its reader, over the
//! room's roster.

use super::{
    clearances_in, peer_read_keys_in, reading_defaults_in, room_facets_axis_in, room_reader_in,
    room_roster_in,
};
use crate::claim::{RoomTerms, RoomTurnCeiling};
use crate::context_board::room::{RoomPresence, room_clearance, room_worlds};
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
/// private thread's (FIX 2951) are over the members in its audience alone.
/// `None` when `caller` does not read the thread here. Held, as the room's.
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
    let members = crate::workspace_roster::thread_members_in(vault, txn, room, thread, &members)?;
    let worlds = reading_defaults_in(vault, txn, &members)?;
    let clearances = clearances_in(vault, txn, &members)?;
    let roster: Vec<_> = members
        .iter()
        .zip(worlds.into_iter().zip(clearances))
        .map(|(member, (active_worlds, clearance))| RoomPresence {
            actor: *member,
            actor_class: None,
            label: String::new(),
            present: true,
            active_worlds,
            clearance,
        })
        .collect();
    let terms = RoomTerms {
        worlds: room_worlds(&roster)?,
        facets: room_facets_axis_in(vault, txn, room)?,
        clearance: room_clearance(&roster),
        p7: true,
    };
    Ok(Some(RoomTurnCeiling {
        room,
        caller,
        terms: crate::claim::TurnTerms::new(terms),
        peers: peer_read_keys_in(vault, txn, caller, &members)?,
        roster: members,
        branch: Some(thread),
        personal: false,
    }))
}
