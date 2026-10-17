//! A room-wide offer card's time (OF-530 ruling A): it stays open while
//! people engage with it, and ages out after a day with none or at the fixed
//! deadline its poster set, which replaces that day.
//!
//! Engagement is a reply, a vote or a mention, each stamped on the stored card
//! by the write that makes it; nothing scans the room for it, and a read or a
//! replay renews nothing. A message mentions a card by naming its id in its
//! metadata's `room_offer_refs`, a DAG record in its body's; a reply engages
//! the cards the turn it answers named, or the nearest turn up its reply chain
//! that names any. A vote is an advisory ballot, join or not now: it keeps the
//! card open and admits no one, and only the host's answer
//! ([`super::offer_settle`]) decides. A thread card ends with its thread
//! ([`super::offer_liveness`]) and is not decided here.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::TURNS;
use super::offer_settle::OfferAnswer;
use super::offers::{
    OFFER_CURRENT, OFFERS, OfferCard, OfferState, StoredOffer, current_key, is_offer_id,
    room_wide_prefix,
};
use crate::conversation_dag::AppendRecord;
use crate::edge::EdgeKind;
use crate::error::{ClaimError, Error, Result};
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::memory::{Memory, MemoryError, MemoryResult, WitnessAuthor, WitnessTurn};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault, WriteActor};

/// How long a room-wide card with no fixed deadline stays open after its
/// last engagement: a day (OF-530 ruling A).
pub(crate) const ROOM_OFFER_IDLE_SECS: u64 = 24 * 60 * 60;

/// The field a message's metadata, or a DAG record's body, names the
/// room-wide cards it mentions in: an array of offer ids.
const OFFER_REFS: &str = "room_offer_refs";

/// Most cards one message or record names, as a turn's mentions.
const MAX_OFFER_REFS: usize = 256;

/// An advisory ballot on a room-wide card, from someone in its room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferVoteRequest {
    pub offer_id: String,
    /// What the voter would have the host answer: join, or not now.
    pub action: OfferAnswer,
}

/// Whether `card`, a room-wide card open in store, has aged out at `now`:
/// past its fixed deadline, or a day past its last engagement when it has
/// none.
pub(super) fn room_offer_expired(card: &OfferCard, now: u64) -> bool {
    card.branch.is_none()
        && matches!(card.state, OfferState::Open { .. })
        && card.until.map_or_else(
            || now.saturating_sub(card.last_engaged_at) >= ROOM_OFFER_IDLE_SECS,
            |until| now >= until,
        )
}

/// Whether `card` is the one current for its agent in its room or thread.
pub(super) fn is_current_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    card: &OfferCard,
) -> Result<bool> {
    Ok(OFFER_CURRENT
        .get(
            &vault.store,
            txn,
            &current_key(card.room, card.branch, card.agent),
        )?
        .as_deref()
        == Some(card.offer_id.as_str()))
}

/// Whether `actor` reads `room` as its audience does: a member, a live Ready
/// join for the room, or its host ([`crate::context_board::room_reader_in`]).
fn reads_room_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
) -> Result<bool> {
    match crate::context_board::room_roster_in(vault, txn, room)? {
        Some(members) => crate::context_board::room_reader_in(vault, txn, room, &members, actor),
        None => Ok(false),
    }
}

fn not_in_room() -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority {
        reason: "only the room's audience engages its offer cards",
    })
}

fn bad_refs() -> Error {
    Error::InvalidConfig("room_offer_refs is an array of this room's room-wide offer ids".into())
}

/// The ids a writer names in [`OFFER_REFS`]: an array of offer ids, or the
/// write is refused.
fn json_refs(value: &serde_json::Value) -> Result<BTreeSet<String>> {
    let ids = value.as_array().ok_or_else(bad_refs)?;
    if ids.len() > MAX_OFFER_REFS {
        return Err(bad_refs());
    }
    ids.iter()
        .map(|id| {
            id.as_str()
                .filter(|id| is_offer_id(id))
                .map(str::to_owned)
                .ok_or_else(bad_refs)
        })
        .collect()
}

/// [`json_refs`] for a MessagePack value.
fn msgpack_refs(value: &rmpv::Value) -> Result<BTreeSet<String>> {
    let ids = value.as_array().ok_or_else(bad_refs)?;
    if ids.len() > MAX_OFFER_REFS {
        return Err(bad_refs());
    }
    ids.iter()
        .map(|id| {
            id.as_str()
                .filter(|id| is_offer_id(id))
                .map(str::to_owned)
                .ok_or_else(bad_refs)
        })
        .collect()
}

/// The field `name` of a MessagePack map.
fn map_field<'a>(map: &'a rmpv::Value, name: &str) -> Option<&'a rmpv::Value> {
    map.as_map()?
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
}

/// The ids a stored body names: in its `within` field when given, else at its
/// top. It was checked when written, so a body that no longer reads names none.
fn stored_body_refs(body: &[u8], within: Option<&str>) -> BTreeSet<String> {
    let Ok(value) = rmpv::decode::read_value(&mut &body[..]) else {
        return BTreeSet::new();
    };
    let holder = match within {
        Some(field) => map_field(&value, field),
        None => Some(&value),
    };
    holder
        .and_then(|holder| map_field(holder, OFFER_REFS))
        .and_then(|refs| msgpack_refs(refs).ok())
        .unwrap_or_default()
}

/// The ids a stored turn names, read back as written: its own TURN body's and
/// each of its MESSAGEs' metadata. `None` when `id` is no live TURN of `room`.
fn stored_refs_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    id: EntityId,
) -> Result<Option<BTreeSet<String>>> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_TURN,
        body,
    } = live_entity_row_in_txn(&vault.store, txn, &id)?
    else {
        return Ok(None);
    };
    if crate::conversation_dag::edge_ids(&vault.store, txn, &id, EdgeKind::ChildOf, false, 2)?
        != [room]
    {
        return Ok(None);
    }
    let mut named = stored_body_refs(&body, None);
    for edge in vault
        .store
        .port_edges(txn, &id, EdgeDirection::In, Some(EdgeKind::PartOf), None)?
    {
        if let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_MESSAGE,
            body,
        } = live_entity_row_in_txn(&vault.store, txn, &edge?.target)?
        {
            named.extend(stored_body_refs(&body, Some("metadata")));
        }
    }
    Ok(Some(named))
}

/// Whether `room` holds an open room-wide card a reply there could engage.
fn open_card_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, room: EntityId) -> Result<bool> {
    for row in OFFER_CURRENT.iter_from(&vault.store, txn, room_wide_prefix(room).as_bytes())? {
        let (_, offer) = row?;
        if OFFERS
            .get(&vault.store, txn, &offer)?
            .is_some_and(|stored| matches!(stored.card.state, OfferState::Open { .. }))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The ids the nearest turn up a reply chain names, from `parent`, the turn a
/// new one answers. Each step is one reply link `up` reads, never a thread's
/// trunk anchor, a `Parent` or a recipient. The walk ends at a turn outside
/// `room`, at the chain's start and at the shared ancestor bound, past which
/// a reply engages no card.
fn inherited_refs_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    parent: EntityId,
    up: impl Fn(EntityId) -> Result<Option<EntityId>>,
) -> Result<BTreeSet<String>> {
    let mut cursor = Some(parent);
    let mut seen = BTreeSet::new();
    while let Some(id) = cursor {
        if !seen.insert(id) || seen.len() > MAX_ANCESTOR_DEPTH {
            break;
        }
        match stored_refs_in_txn(vault, txn, room, id)? {
            None => break,
            Some(named) if !named.is_empty() => return Ok(named),
            Some(_) => cursor = up(id)?,
        }
    }
    Ok(BTreeSet::new())
}

/// Engages, in one write by `actor`, the room-wide cards of `room` it names
/// (`named`, each of which must be one) and those it inherits from the turn
/// it answers (`inherited`, read back as stored). A card is engaged only while
/// open and current for its agent; one past its time is stamped aged out
/// instead, and stays so. A fixed deadline never moves. A writer outside the
/// room's audience names no card, and inherits none.
fn engage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    actor: WriteActor,
    named: &BTreeSet<String>,
    inherited: &BTreeSet<String>,
) -> Result<()> {
    if named.is_empty() && inherited.is_empty() {
        return Ok(());
    }
    vault.verify_write_actor_in_txn(txn, &actor)?;
    if !reads_room_in_txn(vault, txn, room, actor.entity_ref())? {
        return if named.is_empty() {
            Ok(())
        } else {
            Err(not_in_room())
        };
    }
    let room_wide = |stored: &StoredOffer| stored.card.room == room && stored.card.branch.is_none();
    let mut cards = Vec::new();
    for offer_id in named {
        let stored = OFFERS
            .get(&vault.store, txn, offer_id)?
            .filter(room_wide)
            .ok_or_else(bad_refs)?;
        cards.push(stored);
    }
    for offer_id in inherited.difference(named) {
        cards.extend(OFFERS.get(&vault.store, txn, offer_id)?.filter(room_wide));
    }
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    for mut stored in cards {
        // A replaced or answered card stays ordinary prose.
        if !matches!(stored.card.state, OfferState::Open { .. })
            || !is_current_in_txn(vault, txn, &stored.card)?
        {
            continue;
        }
        if room_offer_expired(&stored.card, now) {
            stored.card.state = OfferState::AgedOut;
        } else if stored.card.last_engaged_at < now {
            stored.card.last_engaged_at = now;
        } else {
            continue;
        }
        OFFERS.put(&vault.store, txn, &stored.card.offer_id, &stored)?;
    }
    Ok(())
}

/// [`engage_in_txn`] for a witnessed turn, in the witness's own write, before
/// its room admits it: the cards its new visible messages name and, in a
/// project room, those the turn it answers names. A retried message, a hidden
/// one or a system line engages nothing.
pub(super) fn witness_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: WriteActor,
    room: EntityId,
    input: &WitnessTurn,
    messages: &[EntityId],
) -> Result<()> {
    let mut named = BTreeSet::new();
    let mut reply_to = None;
    for (message, id) in input.messages.iter().zip(messages) {
        let Some(metadata) = message.metadata.as_ref() else {
            continue;
        };
        let refs = metadata.get(OFFER_REFS);
        // The room's own admission proves this link below, in this write.
        let reply = metadata
            .get("room_reply_to")
            .and_then(serde_json::Value::as_str);
        if message.author == WitnessAuthor::System
            || !message.is_visible
            || (refs.is_none() && reply.is_none())
            || vault.get_entity_type_in_txn(txn, id)?.is_some()
        {
            continue;
        }
        if let Some(refs) = refs {
            named.extend(json_refs(refs)?);
        }
        reply_to = reply_to.or_else(|| reply.and_then(|id| EntityId::from_hex(id).ok()));
    }
    if named.is_empty() && reply_to.is_none() {
        return Ok(());
    }
    let read: &heed::RoTxn<'_> = &*txn;
    let inherited = match reply_to {
        Some(parent)
            if super::super::project::ROOM_PROJECT.contains(&vault.store, read, &room)?
                && open_card_in_txn(vault, read, room)? =>
        {
            inherited_refs_in_txn(vault, read, room, parent, |id| {
                TURNS
                    .get(&vault.store, read, &id)?
                    .filter(|turn| turn.room_id == room.to_hex())
                    .and_then(|turn| turn.reply_to)
                    .map(|reply| EntityId::from_hex(&reply))
                    .transpose()
            })?
        }
        _ => BTreeSet::new(),
    };
    engage_in_txn(vault, txn, room, actor, &named, &inherited)
}

/// [`engage_in_txn`] for a live DAG append, in its own write once its writer
/// has joined: the cards its body names, and those the record it answers,
/// `reply_to`, or the nearest record up that reply chain names.
pub(crate) fn record_offer_append_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: &AppendRecord,
    reply_to: Option<EntityId>,
) -> Result<()> {
    let body = rmpv::decode::read_value(&mut input.body.as_slice())
        .map_err(|_| Error::InvariantViolation("checked record body"))?;
    let named = map_field(&body, OFFER_REFS)
        .map(msgpack_refs)
        .transpose()?
        .unwrap_or_default();
    let room = input.conversation;
    let read: &heed::RoTxn<'_> = &*txn;
    let inherited = match reply_to {
        Some(parent) if open_card_in_txn(vault, read, room)? => {
            inherited_refs_in_txn(vault, read, room, parent, |id| {
                Ok(crate::conversation_dag::edge_ids(
                    &vault.store,
                    read,
                    &id,
                    EdgeKind::RepliesTo,
                    false,
                    2,
                )?
                .first()
                .copied())
            })?
        }
        _ => BTreeSet::new(),
    };
    engage_in_txn(vault, txn, room, input.actor, &named, &inherited)
}

impl Memory<'_> {
    /// Casts the caller's advisory ballot on a room-wide card, as someone in
    /// its room. A new or changed ballot engages the card; the same one again
    /// changes nothing. It records no consent, files no join and lands no
    /// turn. A card that has ended takes no ballot and comes back as it
    /// stands; it is never reopened by one.
    pub fn rooms_offer_vote(&self, request: &OfferVoteRequest) -> MemoryResult<OfferCard> {
        if !is_offer_id(&request.offer_id) {
            return Err(MemoryError::bad_request(
                "offer_id is the 64-hex id rooms.offer returned",
            ));
        }
        let vault = self.vault();
        let room = {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            OFFERS
                .get(&vault.store, &txn, &request.offer_id)?
                .ok_or_else(|| MemoryError::not_found("no offer card under this offer_id"))?
                .card
                .room
        };
        self.require_offer_audience(room, None)?;
        let caller = WriteActor::new(self.actor(), self.actor_class());
        vault.try_with_write_txn_grouped(|txn| {
            let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            vault.verify_write_actor_in_txn(txn, &caller)?;
            let mut stored = OFFERS
                .get(&vault.store, txn, &request.offer_id)?
                .ok_or_else(|| MemoryError::not_found("no offer card under this offer_id"))?;
            if stored.card.branch.is_some() {
                return Err(MemoryError::bad_request(
                    "a vote is cast on a room-wide offer only",
                ));
            }
            if !reads_room_in_txn(vault, txn, stored.card.room, caller.entity_ref())? {
                return Err(MemoryError::from(not_in_room()));
            }
            if !matches!(stored.card.state, OfferState::Open { .. })
                || !is_current_in_txn(vault, txn, &stored.card)?
            {
                return Ok(stored.card);
            }
            if room_offer_expired(&stored.card, now) {
                stored.card.state = OfferState::AgedOut;
            } else if stored.votes.get(&caller.entity_ref()) == Some(&request.action) {
                return Ok(stored.card);
            } else {
                stored.votes.insert(caller.entity_ref(), request.action);
                stored.card.last_engaged_at = stored.card.last_engaged_at.max(now);
            }
            OFFERS.put(&vault.store, txn, &request.offer_id, &stored)?;
            Ok(stored.card)
        })
    }
}
