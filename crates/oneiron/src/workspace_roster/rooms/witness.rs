//! Claim-before-speaking guard inside the existing witness transaction.
use super::participation::{
    addressable_agent_in_txn, admit_speech_in, agent_standing_in_txn, participant_in_txn,
    record_addressed_in_txn, thread_root_in_txn,
};
use super::*;
use crate::edge::EdgeActorClass;
use crate::memory::{WitnessAuthor, WitnessTurn};
use crate::workspace_roster::JoinSubject;

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
    if !super::super::project::ROOM_PROJECT.contains(&vault.store, txn, &room)? {
        return Ok(());
    }
    // OF-529: an agent needs no seat: it stands on a Ready receipt, checked
    // once its thread is known. A person stands on its seat or a live Ready
    // join, or joins by this write, at the participation gate below (OF-417).
    let now = vault.store.clock.now_recorded_at();
    let speaker = participant_in_txn(vault, txn, actor, now)?;
    let current_room = match speaker {
        Some(_) => room_in(vault, txn, room)?,
        None => require_member(vault, txn, room, actor)?,
    };
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
                // Unknown mentions fail closed rather than opening the turn
                // to every companion in the room.
                let addressed = HANDLES
                    .get(&vault.store, txn, &(room, handle.to_owned()))?
                    .ok_or_else(invalid)?;
                // An agent may be named without a seat: naming enrolls no
                // one and grants nothing (OF-529).
                if !current_room.member_ids.contains(&addressed.to_hex())
                    && !addressable_agent_in_txn(vault, txn, addressed, now)?
                {
                    return Err(invalid());
                }
                mentions.insert(addressed.to_hex());
            }
        }
    }
    // A reply within an existing thread inherits its trunk anchor. This is
    // the same thread_of fact the room index uses to keep HEAD on the trunk;
    // neither an omitted metadata field nor a nested reply may advance HEAD.
    if let Some(parent) = reply_to {
        let mut cursor = Some(parent);
        let mut seen = BTreeSet::new();
        while let Some(id) = cursor {
            if !seen.insert(id) || seen.len() > 100_000 {
                return Err(invalid());
            }
            let ancestor = turn_in(vault, txn, id)?;
            if ancestor.room_id != room.to_hex() {
                return Err(invalid());
            }
            if let Some(anchor) = ancestor.thread_of {
                let anchor = EntityId::from_hex(&anchor)?;
                if thread_of.is_some_and(|explicit| explicit != anchor) {
                    return Err(invalid());
                }
                thread_of = Some(anchor);
                break;
            }
            cursor = ancestor
                .reply_to
                .as_deref()
                .map(EntityId::from_hex)
                .transpose()?;
        }
    }
    // The participation gate (OF-529): the thread this turn lands in is its
    // root, and a person's turn is its join there.
    let branch = thread_root_in_txn(vault, txn, turn_id, reply_to, thread_of)?;
    let admitted = super::admit_participation_in_txn(
        vault,
        txn,
        room,
        branch,
        crate::WriteActor::new(actor, class),
        JoinCause::Wrote { turn: turn_id },
        None,
        now,
    )?;
    let standing = match speaker {
        Some(JoinSubject::Agent(agent)) => Some(
            agent_standing_in_txn(vault, txn, room, branch, agent, None)?.ok_or_else(invalid)?,
        ),
        _ => None,
    };
    // An agent cannot masquerade as a user to evade a claim. The witness
    // author ceiling remains an additional, independent gate below this one.
    let is_response = class != EdgeActorClass::Human
        || input
            .messages
            .iter()
            .any(|m| m.author == WitnessAuthor::Companion);
    // An accepted offer card lands as the agent's own turn (OF-530): the
    // settlement that made its join Ready bound exactly this turn to the
    // offer and its thread in this write, in place of a claim on an
    // addressed turn. The speaking role and the author ceiling still decide.
    let accepted_offer = is_response
        && super::offers::accepts_offer_in_txn(vault, txn, room, branch, actor, turn_id)?;
    if accepted_offer {
        admit_speech_in(vault, txn, room, actor, standing.as_ref())?;
    } else if is_response {
        // Only a speaker who speaks as a persona answers; the claim door
        // checks the same, and upkeep never holds one.
        admit_speech_in(vault, txn, room, actor, standing.as_ref())?;
        let parent = reply_to.ok_or_else(invalid)?;
        let claim = CLAIMS
            .get(&vault.store, txn, &parent)?
            .ok_or_else(invalid)?;
        if claim.actor != actor.to_hex() || claim.room_id != room.to_hex() {
            return Err(invalid());
        }
        if let Some(prior) = RESPONSE.get(&vault.store, txn, &parent)?
            && prior != turn_id
        {
            return Err(invalid());
        }
        RESPONSE.put(&vault.store, txn, &parent, &turn_id)?;
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
        task_ids: Vec::new(),
        converted_project: None,
    };
    if let Some(old) = TURNS.get(&vault.store, txn, &turn_id)? {
        if old.actor != turn.actor
            || old.room_id != turn.room_id
            || old.addressed_agents != turn.addressed_agents
            || old.reply_to != turn.reply_to
            || old.thread_of != turn.thread_of
        {
            return Err(invalid());
        }
        turn.at = old.at;
        turn.task_ids = old.task_ids;
        turn.converted_project = old.converted_project;
        let mut all = old.message_ids;
        for id in &turn.message_ids {
            if !all.contains(id) {
                all.push(id.clone());
            }
        }
        turn.message_ids = all;
    }
    TURNS.put(&vault.store, txn, &turn_id, &turn)?;
    super::history::index_turn(&vault.store, txn, &turn)?;
    admitted.record_in_txn(vault, txn, now)?;
    record_addressed_in_txn(
        vault,
        txn,
        room,
        branch,
        turn_id,
        &turn.addressed_agents,
        now,
    )
}
