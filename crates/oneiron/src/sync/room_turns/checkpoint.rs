//! A room turn row in a checkpoint (KS7-3a, KS7-3b), read with the turn
//! codec: the row rides with its TURN, held only while its room, its
//! messages and each turn it quotes are. Its actor and the agents it
//! addressed are split out (FIX 9127): the copy keeps the turn naming no one
//! and addressing no one, and each actor is a field of its own. An actor
//! that does not open leaves the erased spelling, and an agent that does not
//! open is no longer addressed. A row naming an actor by anything but its
//! id stays unclassified.
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::{decode, encode};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::store::checkpoint_payload::rows::{NOT_SPELLED_BACK, OwnerRef, bad_part};
use crate::sync::carrier_parts::is_part_key;
use crate::sync::checkpoint_payload::{Holder, Placement, SyncUnclassified, ValueSplit};
use crate::workspace_roster::RoomTurn;

/// A turn row naming its actor or an agent it addressed by anything but an
/// id.
const TURN_ACTORS: &str = "a room turn names an actor by something other than its id";

/// A turn row in parts (FIX 11790): only the joined row's split takes its
/// actors out, so the manifest and its parts stay unclassified, named with
/// the turn.
const PARTED_TURN: &str =
    "a room turn row in parts, whose actors only its joined row's split takes out";

/// The field the turn's actor fills.
const ACTOR: &str = "actor";

/// The field an addressed agent fills, then its place among them.
const ADDRESSED: &str = "addressed/";

/// An id in its one canonical spelling.
fn named(hex: &str) -> Option<EntityId> {
    EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
}

/// Where the turn row under `key` goes.
pub(in crate::sync) fn entry(key: &str, value: &[u8]) -> Placement {
    let undecodable = || Placement::unclassified(None, SyncUnclassified::Undecodable);
    // FIX 11790: a part goes with the manifest that lists it, and a manifest
    // under the turn its key names.
    if is_part_key(key) {
        return Placement::Part;
    }
    if let Some(parts) = crate::sync::room_parts::manifest(value) {
        return named(key).map_or_else(undecodable, |id| Placement::Manifest {
            holders: vec![Holder::new(OwnerRef::entity(&id), Vec::new())],
            parts,
            joined: Some(SyncUnclassified::ActorSplit(PARTED_TURN)),
        });
    }
    let Ok(turn) = decode(value) else {
        return undecodable();
    };
    let (Some(id), Some(room)) = (named(&turn.turn_id), named(&turn.room_id)) else {
        return undecodable();
    };
    if turn.turn_id != key {
        return undecodable();
    }
    let owner = OwnerRef::entity(&id);
    let mut dependencies = vec![OwnerRef::entity(&room)];
    for message in &turn.message_ids {
        let Some(message) = named(message) else {
            return undecodable();
        };
        dependencies.push(OwnerRef::entity(&message));
    }
    dependencies.extend(
        turn.quotes
            .values()
            .map(|quote| OwnerRef::entity(&quote.target_turn)),
    );
    match split(turn, value) {
        Ok(split) => Placement::split(vec![Holder::new(owner, dependencies)], split),
        Err(reason) => Placement::unclassified(Some(owner), SyncUnclassified::ActorSplit(reason)),
    }
}

/// `turn`, stored as `value`, naming no one and addressing no one, and each
/// actor it named.
fn split(mut turn: RoomTurn, value: &[u8]) -> std::result::Result<ValueSplit, &'static str> {
    if encode(&turn).ok().as_deref() != Some(value) {
        return Err(NOT_SPELLED_BACK);
    }
    let mut actors = Vec::new();
    if turn.actor != ERASED_CALL_IDENTITY {
        actors.push((ACTOR.to_owned(), named(&turn.actor).ok_or(TURN_ACTORS)?));
        turn.actor = ERASED_CALL_IDENTITY.to_owned();
    }
    for (place, agent) in std::mem::take(&mut turn.addressed_agents)
        .iter()
        .enumerate()
    {
        let agent = named(agent).ok_or(TURN_ACTORS)?;
        actors.push((format!("{ADDRESSED}{place}"), agent));
    }
    let no_one = encode(&turn).map_err(|_| TURN_ACTORS)?;
    Ok(ValueSplit { no_one, actors })
}

/// The turn `no_one` with each of `opened` back: its actor, and each agent
/// it addressed.
pub(in crate::sync) fn fill(no_one: &[u8], opened: &[(&str, EntityId)]) -> Result<Option<Vec<u8>>> {
    let mut turn = decode(no_one).map_err(|_| bad_part())?;
    if turn.actor != ERASED_CALL_IDENTITY || !turn.addressed_agents.is_empty() {
        return Err(bad_part());
    }
    for (field, actor) in opened {
        if *field == ACTOR && turn.actor == ERASED_CALL_IDENTITY {
            turn.actor = actor.to_hex();
            continue;
        }
        let placed = field
            .strip_prefix(ADDRESSED)
            .is_some_and(|place| place.parse::<usize>().is_ok());
        if !placed || !turn.addressed_agents.insert(actor.to_hex()) {
            return Err(bad_part());
        }
    }
    encode(&turn).map(Some)
}
