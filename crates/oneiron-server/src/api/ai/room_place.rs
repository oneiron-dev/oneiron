//! Where a chat turn or a voice call works in a room (FIX 3572): the room,
//! and the thread a join files the work under, read from the work's TURN
//! the way the turn-action worker reads a Continue's or Retry's. A join
//! filed for that thread then funds the work before the room's own.
//! Entry: `reply_place`, `call_place`, `stamp_reply`.

use oneiron::memory::WitnessTurn;
use oneiron::workspace_roster::RoomWork;
use oneiron::{EntityId, Vault};

/// The message metadata key a room's witness reads a reply's parent TURN
/// from.
const ROOM_REPLY_TO: &str = "room_reply_to";

/// Where a reply to `turn` in `room` lands: `turn`'s thread, by its root,
/// for a TURN of one of `room`'s threads; `room`'s trunk for a trunk TURN,
/// for no turn, and for a turn of another room's thread, which the room's
/// witness refuses as a reply here.
pub(crate) fn reply_place(
    vault: &Vault,
    room: EntityId,
    turn: Option<EntityId>,
) -> oneiron::Result<RoomWork> {
    let trunk = RoomWork { room, branch: None };
    let Some(turn) = turn else {
        return Ok(trunk);
    };
    Ok(vault
        .turn_room_work(turn)?
        .filter(|work| work.room == room)
        .unwrap_or(trunk))
}

/// The place `place` names for a call: a room, or one of its threads by any
/// TURN of that thread, whose room is the call's container.
pub(crate) fn call_place(vault: &Vault, place: EntityId) -> oneiron::Result<RoomWork> {
    Ok(vault.turn_room_work(place)?.unwrap_or(RoomWork {
        room: place,
        branch: None,
    }))
}

/// Marks `turn`'s messages as a reply to `parent`: the room's witness lands
/// them in `parent`'s thread, or opens one on a trunk `parent`.
pub(crate) fn stamp_reply(turn: &mut WitnessTurn, parent: EntityId) {
    for message in &mut turn.messages {
        let metadata = message
            .metadata
            .get_or_insert_with(|| serde_json::json!({}));
        if let Some(fields) = metadata.as_object_mut() {
            fields.insert(ROOM_REPLY_TO.to_owned(), parent.to_hex().into());
        }
    }
}
