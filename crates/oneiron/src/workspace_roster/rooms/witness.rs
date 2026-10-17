//! Claim-before-speaking guard inside the existing witness transaction.
use super::audience::{
    ThreadBinding, thread_audience_allows_in, thread_audience_in, thread_binding,
    thread_root_readable_in, validate_private_audience_in,
};
use super::participation::{
    addressable_agent_in_txn, admit_speech_in, agent_standing_in_txn, participant_in_txn,
    record_addressed_in_txn, thread_root_in_txn,
};
use super::*;
use crate::conversation_dag::{ProvenRoomQuote, QuotedReply};
use crate::edge::EdgeActorClass;
use crate::memory::{WitnessAuthor, WitnessTurn};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::workspace_roster::JoinSubject;

/// A quote rides a turn in a project room (OF-460).
fn quote_outside_project() -> Error {
    Error::InvalidConfig("a room quote rides a turn in a project room".into())
}

/// What the room guard proved for one witness.
pub(crate) struct RoomWitness {
    /// A thread reply's proven quote, which the witness mints into the
    /// TURN's first body and write (OF-460). A trunk turn's quote is kept in
    /// its room row instead, and its TURN is minted opaque: `None`.
    pub(crate) quoted: Option<QuotedReply>,
    /// The thread binding a minted TURN is born with (FIX 2951): its root
    /// and, on the root, the audience it names. A stored TURN already holds
    /// the same one. `None` for a trunk turn, or outside a project room.
    pub(crate) thread: Option<ThreadBinding>,
}

/// The guard every base witness passes in its write transaction: the
/// room's claim, participation and quote rules, and a thread's audience
/// (FIX 2951), checked before any message.
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
) -> Result<RoomWitness> {
    // OF-530 ruling A: a room-wide offer card a new message names, or a
    // reply answers, is engaged in this write: here in an ordinary room, and
    // in a project room once its writer is admitted below.
    let writer = crate::WriteActor::new(actor, class);
    // A stored TURN keeps the thread it was born in (FIX 2951).
    let stored = match live_entity_row_in_txn(&vault.store, txn, &turn_id)? {
        LiveEntityRow::Live {
            entity_type: crate::registry::ENTITY_TYPE_TURN,
            body,
        } => Some(thread_binding(&body)?),
        _ => None,
    };
    if !super::super::project::ROOM_PROJECT.contains(&vault.store, txn, &room)? {
        if input.quote.is_some() {
            return Err(quote_outside_project());
        }
        // An ordinary room's thread opens on its DAG, so a witness opens
        // none; one adding to a private thread's TURN writes from its
        // audience.
        if input.thread_audience.is_some() {
            return Err(invalid());
        }
        if let Some(Some(binding)) = &stored
            && !thread_root_readable_in(vault, txn, binding.root, &[actor])?
        {
            return Err(invalid());
        }
        super::offer_activity::witness_in_txn(vault, txn, writer, room, input, messages)?;
        return Ok(RoomWitness {
            quoted: None,
            thread: None,
        });
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
    // FIX 2951: the binding this turn is born with, or holds. A thread's
    // root names its audience once, at birth: a retry keeps it, and a set it
    // restates must be the same one. Every later turn names that root and
    // writes there only from its audience, which the participation gate
    // checks; the root's own later writes are checked here.
    let thread = match branch {
        None if input.thread_audience.is_some() => return Err(invalid()),
        None => None,
        Some(root) if root == turn_id => Some(match &stored {
            Some(Some(binding)) => {
                if binding.root != turn_id
                    || input
                        .thread_audience
                        .as_ref()
                        .is_some_and(|set| Some(set) != binding.audience.as_ref())
                    || !thread_audience_allows_in(vault, txn, room, turn_id, actor)?
                {
                    return Err(invalid());
                }
                binding.clone()
            }
            // A stored root born without one never takes an audience later.
            Some(None) if input.thread_audience.is_some() => return Err(invalid()),
            Some(None) | None => {
                if let Some(audience) = &input.thread_audience {
                    validate_private_audience_in(vault, txn, room, actor, audience)?;
                }
                ThreadBinding {
                    root: turn_id,
                    audience: input.thread_audience.clone(),
                }
            }
        }),
        Some(root) => {
            let binding = ThreadBinding {
                root,
                audience: None,
            };
            if input.thread_audience.is_some()
                || matches!(&stored, Some(Some(held)) if *held != binding)
            {
                return Err(invalid());
            }
            Some(binding)
        }
    };
    let admitted = super::admit_participation_in_txn(
        vault,
        txn,
        room,
        branch,
        writer,
        JoinCause::Wrote { turn: turn_id },
        reply_to,
        None,
        now,
    )?;
    // A private thread names only its audience: a mention hands the named
    // agent the turn.
    let private = match &thread {
        Some(binding) if binding.root == turn_id => binding.audience.clone(),
        Some(binding) => thread_audience_in(vault, txn, room, binding.root)?,
        None => None,
    };
    if let Some(audience) = &private
        && mentions
            .iter()
            .any(|named| !EntityId::from_hex(named).is_ok_and(|id| audience.contains(&id)))
    {
        return Err(invalid());
    }
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
    // OF-460: the quote is proven in this write against the reply's own
    // thread chain, never moved onto the quoted target, so a thread reply
    // may quote a trunk message. A thread's root, which names its anchor
    // and answers no turn, continues the anchor. The claim parent above
    // stays `reply_to`. A trunk turn's quote reads from the trunk alone and
    // is kept in its room row: the TURN stays opaque and unchained, so the
    // room's DAG keeps its one trunk root.
    let mut trunk_quote = None;
    let quoted = match (input.quote, thread_of) {
        (None, _) => None,
        (Some(quote), Some(anchor)) => {
            let parent = dag_parent_in_txn(vault, txn, anchor, reply_to.unwrap_or(anchor))?;
            Some(QuotedReply::prove_in_txn(
                vault,
                txn,
                room,
                parent,
                crate::WriteActor::new(actor, class),
                quote,
                turn_id,
            )?)
        }
        (Some(quote), None) => {
            trunk_quote = Some(ProvenRoomQuote::prove_in_txn(
                vault,
                txn,
                room,
                None,
                crate::WriteActor::new(actor, class),
                quote,
                turn_id,
            )?);
            None
        }
    };
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
        quote: trunk_quote.as_ref().map(ProvenRoomQuote::metadata),
    };
    let old = TURNS.get(&vault.store, txn, &turn_id)?;
    // A kept quote is immutable: an append or retry carries the same one and
    // never re-pins it; only its first attachment writes the citation pin.
    match (
        &trunk_quote,
        old.as_ref().and_then(|old| old.quote.as_ref()),
    ) {
        (Some(proven), Some(stored)) => proven.require_stored_in_txn(vault, txn, stored)?,
        (Some(proven), None) if old.is_none() => proven.pin_in_txn(vault, txn)?,
        (None, None) => {}
        _ => return Err(invalid()),
    }
    if let Some(old) = old {
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
    )?;
    super::offer_activity::witness_in_txn(vault, txn, writer, room, input, messages)?;
    Ok(RoomWitness { quoted, thread })
}

/// The record a quoted thread reply's DAG chain continues: the nearest turn
/// up its room reply chain that the DAG holds as a thread record, or the
/// thread's trunk `anchor`. Unquoted replies carry no DAG chain, so the
/// quoted ones chain onto each other, and never onto the quoted target.
fn dag_parent_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    anchor: EntityId,
    reply_to: EntityId,
) -> Result<EntityId> {
    let mut cursor = reply_to;
    let mut seen = BTreeSet::new();
    while cursor != anchor
        && !crate::conversation_dag::is_thread_record(&vault.store, txn, &cursor)?
    {
        if !seen.insert(cursor) || seen.len() > 100_000 {
            return Err(invalid());
        }
        match turn_in(vault, txn, cursor)?.reply_to {
            Some(parent) => cursor = EntityId::from_hex(&parent)?,
            None => return Ok(anchor),
        }
    }
    Ok(cursor)
}
