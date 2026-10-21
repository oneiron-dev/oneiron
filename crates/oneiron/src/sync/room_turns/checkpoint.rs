//! A room turn row in a checkpoint (KS7-3a), read with the turn codec: the
//! row rides with its TURN, held only while its room, its messages and each
//! turn it quotes are. A row naming its actor, or agents it addressed,
//! stays unclassified: no split here takes them out.
#![allow(
    dead_code,
    reason = "KS7-3b's Loro projection drives this; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use super::decode;
use crate::entity_id::EntityId;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::sync::checkpoint_payload::{Placement, SyncUnclassified};

/// A turn row naming its actor or the agents it addressed.
const TURN_ACTORS: &str = "a room turn names its actor and the agents it addressed";

/// An id in its one canonical spelling.
fn named(hex: &str) -> Option<EntityId> {
    EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
}

/// Where the turn row under `key` goes.
pub(in crate::sync) fn entry(key: &str, value: &[u8]) -> Placement {
    let undecodable = || Placement::unclassified(None, SyncUnclassified::Undecodable);
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
    if turn.actor != ERASED_CALL_IDENTITY || !turn.addressed_agents.is_empty() {
        return Placement::unclassified(Some(owner), SyncUnclassified::ActorSplit(TURN_ACTORS));
    }
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
    Placement::owned(owner, dependencies)
}
