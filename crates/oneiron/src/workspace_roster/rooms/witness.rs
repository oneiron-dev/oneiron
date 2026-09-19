//! Claim-before-speaking guard inside the existing witness transaction.
use super::*;
use crate::edge::EdgeActorClass;
use crate::memory::{WitnessAuthor, WitnessTurn};

#[expect(
    clippy::too_many_arguments,
    reason = "binds the witness transaction to its resolved actor, container and message ids"
)]
pub(crate) fn admit_witness(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    class: EdgeActorClass,
    room: EntityId,
    turn_id: EntityId,
    input: &WitnessTurn,
    messages: &[EntityId],
) -> Result<()> {
    if vault
        .store
        .vault_meta
        .get(
            txn,
            &[super::super::project::ROOM_PROJECT, room.as_bytes()].concat(),
        )?
        .is_none()
    {
        return Ok(());
    }
    let current_room = require_member(vault, txn, room, actor)?;
    let mut mentions = BTreeSet::new();
    let mut reply_to = None;
    let mut thread_of = None;
    for message in &input.messages {
        let metadata = message.metadata.as_ref();
        for (field, out) in [
            ("room_reply_to", &mut reply_to),
            ("room_thread_of", &mut thread_of),
        ] {
            if let Some(value) = metadata.and_then(|m| m.get(field)) {
                let id = EntityId::from_hex(value.as_str().ok_or_else(invalid)?)?;
                if out.as_ref().is_some_and(|prior| *prior != id) {
                    return Err(invalid());
                }
                let parent = turn_in(vault, txn, id)?;
                if parent.room_id != room.to_hex() {
                    return Err(invalid());
                }
                *out = Some(id);
            }
        }
        if let Some(value) = metadata.and_then(|m| m.get("room_mentions")) {
            let handles = value.as_array().ok_or_else(invalid)?;
            if handles.len() > 256 {
                return Err(invalid());
            }
            for handle in handles {
                let handle = handle.as_str().ok_or_else(invalid)?;
                let key = [HANDLES, room.as_bytes(), handle.as_bytes()].concat();
                // Unknown mentions fail closed rather than opening the turn
                // to every companion in the room.
                let bytes = vault.store.vault_meta.get(txn, &key)?.ok_or_else(invalid)?;
                let addressed =
                    EntityId::from_bytes(bytes.as_ref().try_into().map_err(|_| invalid())?)?
                        .to_hex();
                if !current_room.member_ids.contains(&addressed) {
                    return Err(invalid());
                }
                mentions.insert(addressed);
            }
        }
    }
    // An agent cannot masquerade as a user to evade a claim. The witness
    // author ceiling remains an additional, independent gate below this one.
    let is_response = class != EdgeActorClass::Human
        || input
            .messages
            .iter()
            .any(|m| m.author == WitnessAuthor::Companion);
    if is_response {
        let parent = reply_to.ok_or_else(invalid)?;
        let key = key(CLAIMS, parent);
        let bytes = vault.store.vault_meta.get(txn, &key)?.ok_or_else(invalid)?;
        let claim: RoomClaimReceipt = decode(&bytes)?;
        if claim.actor != actor.to_hex() || claim.room_id != room.to_hex() {
            return Err(invalid());
        }
        let response_key = [b"rooms.response.v1/", parent.as_bytes().as_slice()].concat();
        if let Some(prior) = vault.store.vault_meta.get(txn, &response_key)?
            && prior.as_ref() != turn_id.as_bytes()
        {
            return Err(invalid());
        }
        vault
            .store
            .vault_meta
            .put(txn, &response_key, turn_id.as_bytes())?;
    }
    let mut turn = RoomTurn {
        turn_id: turn_id.to_hex(),
        room_id: room.to_hex(),
        actor: actor.to_hex(),
        addressed_agents: mentions,
        message_ids: messages.iter().map(EntityId::to_hex).collect(),
        reply_to: reply_to.map(|id| id.to_hex()),
        thread_of: thread_of.map(|id| id.to_hex()),
        at: input.occurred_at,
    };
    if let Some(bytes) = vault.store.vault_meta.get(txn, &key(TURNS, turn_id))? {
        let old: RoomTurn = decode(&bytes)?;
        if old.actor != turn.actor
            || old.room_id != turn.room_id
            || old.addressed_agents != turn.addressed_agents
            || old.reply_to != turn.reply_to
            || old.thread_of != turn.thread_of
        {
            return Err(invalid());
        }
        turn.at = old.at;
        let mut all = old.message_ids;
        for id in &turn.message_ids {
            if !all.contains(id) {
                all.push(id.clone());
            }
        }
        turn.message_ids = all;
    }
    vault
        .store
        .vault_meta
        .put(txn, &key(TURNS, turn_id), &encode(&turn)?)?;
    Ok(())
}
