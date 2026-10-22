//! The one ceiling construction a room and each of its threads share (ARCH-0067 §8, OF-529,
//! FIX 1599), run after each one's own reader check, and the room's signed facets it reads
//! in, which a named-room read outside a turn meets too (FIX 643).

use super::{clearances_in, peer_read_keys_in, reading_defaults_in};
use crate::claim::{RoomTerms, RoomTurnCeiling};
use crate::context_board::room::{RoomPresence, room_clearance, room_worlds};
use crate::federation::{Scope, ScopeAxis, ScopeId};
use crate::{EntityId, Vault};

/// The facets `room` limits its reads to as `txn` reads it, from its
/// project's signed slice alone; `All` is a room with no facet.
pub(crate) fn room_facets_axis_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> crate::Result<ScopeAxis<ScopeId>> {
    Ok(crate::workspace_roster::room_facets_in(vault, txn, room)?.unwrap_or(ScopeAxis::All))
}

/// The held ceiling `members` put on `caller`'s reads of `room` as `txn`
/// reads them: their met worlds, the room's signed facets, their met
/// clearance with `extra` beside it (the room's live speakers', or a
/// privileged reader's off the room), P7, and every other member's read key.
/// Its audience is `members` and it reads the room itself; a caller that
/// hears more, or reads one thread, sets those after.
pub(super) fn room_turn_ceiling_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    caller: EntityId,
    members: &[EntityId],
    extra: Option<&Scope>,
) -> crate::Result<RoomTurnCeiling> {
    let worlds = reading_defaults_in(vault, txn, members)?;
    let clearances = clearances_in(vault, txn, members)?;
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
        clearance: crate::claim::meet_clearance(room_clearance(&roster).as_ref(), extra),
        p7: true,
    };
    Ok(RoomTurnCeiling {
        room,
        caller,
        terms: crate::claim::TurnTerms::new(terms),
        peers: peer_read_keys_in(vault, txn, caller, members)?,
        roster: members.to_vec(),
        branch: None,
        personal: false,
    })
}
