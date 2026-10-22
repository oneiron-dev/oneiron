//! OF-522: a room's turn rows on the owner's other machines. Each turn row,
//! with its thread-task bindings and conversion mark, rides the window its
//! TURN rides (`crate::sync::rooms`). A machine that takes one merges it here
//! as the witness door's append does, and indexes the room's history from it.
//!
//! Entry: `merge_replicated_turn_in_txn`.
//! Join, offer and response merges live in `shared`; carrier and refusal types stay here.
use std::collections::BTreeMap;

use super::super::join_receipt::{JOINS, READY, intent_digest, is_join_ref, join_ref, ready_key};
use super::carrier_erase;
use super::fact_subject::FactSubject;
use super::offers::{
    OFFER_CURRENT, OFFERS, OfferBallot, OfferState, StoredOffer, current_key, is_offer_id,
};
use super::*;
use crate::workspace_roster::{JoinDecision, JoinReceipt, JoinSubject};

mod shared;
use self::shared::{fact_order, merge_shared_in_txn};
pub(crate) use self::shared::{
    merge_replicated_responses_in_txn, merge_replicated_shared_row_in_txn, merged_shared_row,
};

/// The turn row this vault holds for `id`, if any.
pub(crate) fn replicated_turn_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<RoomTurn>> {
    TURNS.get(&vault.store, txn, &id)
}

/// Why this vault refuses a carried turn row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TurnMergeRefusal {
    /// The row names ids that do not parse.
    InvalidIds,
    /// The row names fixed fields other than the row this vault holds.
    FixedFieldsConflict,
    /// This vault deleted the row's room; no room deletion is undone.
    RoomDeleted,
    /// This vault holds no record of the row's room.
    RoomMissing,
    /// This vault erased the thread a fact names; no thread erase is undone.
    ThreadDeleted,
    /// Two copies of one join or offer card settle otherwise: two settled
    /// decisions, two answers, or one voter's two ballots under one stamp.
    /// Neither is chosen silently.
    DecisionConflict,
    /// This vault erased an actor the row waits on or names by id, and the
    /// erase took the row out here (FIX 4227, 4228); no erase is undone.
    ActorErased,
}

/// What merging a carried turn row did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TurnMerge {
    /// The row this vault holds changed, and its history is indexed.
    Written,
    /// This vault holds everything the row carries.
    Held,
    /// The row is left out, for the reason given.
    Refused(TurnMergeRefusal),
}

/// Merges a turn row another machine of this vault carried. A row this vault
/// lacks is written as carried. One it holds keeps its room, actor,
/// addressing, links, time and conversion, and takes the carried messages,
/// bound tasks and message quotes it lacks; a carried row that names other
/// fixed fields, or another quote for a message this vault's row already
/// keeps one for (FIX 2028), is refused. A quote is kept only against a
/// message the row names. A row whose room this vault deleted, or holds no
/// record of, is refused before anything is written, so no turn or history
/// row dangles from a room that is gone (OF-522). An actor erased on either
/// side names no one in the merged row (FIX 6543): the carried copy's actor
/// this vault erased reads as the erased form, and that form wins over a
/// live actor for the same turn, as every carrier merge settles who it
/// names ([`crate::deletion::ACTOR_ERASE_CARRIER_MERGE`]).
pub(crate) fn merge_replicated_turn_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    mut carried: RoomTurn,
) -> Result<TurnMerge> {
    const ERASED: &str = crate::receipt::ERASED_CALL_IDENTITY;
    let named = |hex: &str| EntityId::from_hex(hex).is_ok_and(|id| id.to_hex() == hex);
    if !named(&carried.turn_id)
        || !named(&carried.room_id)
        || !(named(&carried.actor) || carried.actor == ERASED)
        || carried.reply_to.as_deref().is_some_and(|id| !named(id))
        || carried.thread_of.as_deref().is_some_and(|id| !named(id))
        || carried
            .quotes
            .keys()
            .any(|citer| !named(citer) || !carried.message_ids.contains(citer))
    {
        return Ok(TurnMerge::Refused(TurnMergeRefusal::InvalidIds));
    }
    let room = EntityId::from_hex(&carried.room_id)?;
    if crate::ports::removed_in_txn(&vault.store, txn, &room)? {
        return Ok(TurnMerge::Refused(TurnMergeRefusal::RoomDeleted));
    }
    if crate::ports::EntityStoreRead::port_entity_record(&vault.store, txn, &room)?.is_none() {
        return Ok(TurnMerge::Refused(TurnMergeRefusal::RoomMissing));
    }
    if let Ok(actor) = EntityId::from_hex(&carried.actor)
        && vault.carrier_actor_erased_in_txn(txn, &actor)?
    {
        carried.actor = ERASED.to_owned();
    }
    let id = EntityId::from_hex(&carried.turn_id)?;
    let merged = match TURNS.get(&vault.store, txn, &id)? {
        None => carried,
        Some(held) => {
            let Some(actor) = crate::deletion::carrier_actor_merged(
                held.actor.as_str(),
                carried.actor.as_str(),
                ERASED,
            )
            .map(str::to_owned) else {
                return Ok(TurnMerge::Refused(TurnMergeRefusal::FixedFieldsConflict));
            };
            if held.room_id != carried.room_id
                || held.addressed_agents != carried.addressed_agents
                || held.reply_to != carried.reply_to
                || held.thread_of != carried.thread_of
                || carried
                    .quotes
                    .iter()
                    .any(|(citer, quote)| held.quotes.get(citer).is_some_and(|kept| kept != quote))
            {
                return Ok(TurnMerge::Refused(TurnMergeRefusal::FixedFieldsConflict));
            }
            let mut merged = held.clone();
            merged.actor = actor;
            for message in carried.message_ids {
                if !merged.message_ids.contains(&message) {
                    merged.message_ids.push(message);
                }
            }
            for task in carried.task_ids {
                if !merged.task_ids.contains(&task) {
                    merged.task_ids.push(task);
                }
            }
            for (citer, quote) in carried.quotes {
                merged.quotes.entry(citer).or_insert(quote);
            }
            if merged.converted_project.is_none() {
                merged.converted_project = carried.converted_project;
            }
            if merged == held {
                return Ok(TurnMerge::Held);
            }
            merged
        }
    };
    TURNS.put(&vault.store, txn, &id, &merged)?;
    history::index_turn(&vault.store, txn, &merged)?;
    Ok(TurnMerge::Written)
}

/// One of a room's side rows on the owner's other machines (FIX 1794), as
/// L09 ruled each table travels. A room's host pin, platform handles and
/// room-wide participation facts ride the window its room rides; a turn's
/// claim and response the window the turn rides; a thread's facts the
/// window of the turn that roots it (`crate::sync::room_facts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "table", rename_all = "snake_case")]
pub(crate) enum RoomSideRow {
    /// A room's stored host.
    HostPin { room: EntityId, pin: HostPin },
    /// A platform handle and the actor it addresses in a room.
    Handle {
        room: EntityId,
        handle: String,
        actor: EntityId,
    },
    /// Who claimed an addressed turn.
    Claim { claim: RoomClaimReceipt },
    /// The turn that answered a claimed turn, and who spoke it when.
    Response {
        room: EntityId,
        parent: EntityId,
        response: EntityId,
        actor: EntityId,
        at: u64,
    },
    /// One participation fact, under the key its place, subject and cause
    /// make.
    Participation {
        room: EntityId,
        branch: Option<EntityId>,
        subject: crate::workspace_roster::JoinSubject,
        at: u64,
        join_ref: Option<String>,
        cause: JoinCause,
    },
    /// A join intent's receipt. A room-wide join rides the window its room
    /// rides, and a thread's join the window of the turn that roots it.
    Join { receipt: JoinReceipt },
    /// An offer card as stored, riding as its join does.
    Offer { offer: StoredOffer },
}

impl RoomSideRow {
    /// The room the row belongs to, and the thread root a fact, join or
    /// card names; `None` when the row names an id that does not parse.
    pub(crate) fn place(&self) -> Option<(EntityId, Option<EntityId>)> {
        match self {
            Self::HostPin { room, .. }
            | Self::Handle { room, .. }
            | Self::Response { room, .. } => Some((*room, None)),
            Self::Claim { claim } => named(&claim.room_id).map(|room| (room, None)),
            Self::Participation { room, branch, .. } => Some((*room, *branch)),
            Self::Join { receipt } => Some((receipt.request.room, receipt.request.branch)),
            Self::Offer { offer } => Some((offer.card.room, offer.card.branch)),
        }
    }

    /// Whether the row keeps its table's shape: ids that parse, a handle
    /// the bind door would take, and a join filed under the ref and digest
    /// its request makes.
    pub(crate) fn well_formed(&self) -> bool {
        match self {
            Self::Handle { handle, .. } => {
                !handle.is_empty() && handle.len() <= 256 && !handle.contains('\0')
            }
            Self::Claim { claim } => {
                named(&claim.room_id).is_some()
                    && named(&claim.turn_id).is_some()
                    && named(&claim.actor).is_some()
            }
            Self::Join { receipt } => {
                join_ref(&receipt.request).is_ok_and(|filed| filed == receipt.join_ref)
                    && intent_digest(&receipt.request)
                        .is_ok_and(|filed| filed == receipt.intent_digest)
            }
            Self::Offer { offer } => {
                is_offer_id(&offer.card.offer_id) && is_join_ref(&offer.card.join_ref)
            }
            _ => true,
        }
    }

    /// The entity whose window carries a join or an offer card, its thread
    /// root or else its room, and the join's ref or the card's id: a window
    /// holds one copy of each, merged on both sides. `None` for the other
    /// tables.
    pub(crate) fn merged_place(&self) -> Option<(EntityId, &str)> {
        match self {
            Self::Join { receipt } => Some((
                receipt.request.branch.unwrap_or(receipt.request.room),
                &receipt.join_ref,
            )),
            Self::Offer { offer } => Some((
                offer.card.branch.unwrap_or(offer.card.room),
                &offer.card.offer_id,
            )),
            _ => None,
        }
    }
}

/// `hex` as an id, when it is one's canonical spelling.
fn named(hex: &str) -> Option<EntityId> {
    EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
}

/// Where a room turn sits, for the side rows that ride beside it (FIX 3094).
enum TurnPlace {
    /// A project room's turn, read from its turn row.
    Row { room: EntityId, turn: Box<RoomTurn> },
    /// An ordinary room's DAG TURN, which has no turn row: the room that owns
    /// it, and the root its thread binding names, `None` for a trunk TURN.
    Dag {
        room: EntityId,
        root: Option<EntityId>,
    },
}

impl TurnPlace {
    fn room(&self) -> EntityId {
        match self {
            Self::Row { room, .. } | Self::Dag { room, .. } => *room,
        }
    }

    /// Whether turn `id`, placed here, roots its thread.
    fn roots(&self, id: EntityId) -> bool {
        match self {
            Self::Row { turn, .. } => super::liveness::is_thread_root(turn),
            Self::Dag { root, .. } => *root == Some(id),
        }
    }
}

/// Where room turn `id` sits (FIX 3094). A project room's turn is read from
/// its turn row; an ordinary room's turn is a DAG TURN, placed by the room
/// that owns it and its door-stamped thread binding, and no turn row is made
/// for it. `None` for a turn of no room, or a DAG TURN whose owner or
/// binding does not resolve, or whose binding names another room.
fn turn_place_in(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<Option<TurnPlace>> {
    let store = &vault.store;
    if let Some(turn) = TURNS.get_lenient(store, txn, &id)? {
        return Ok(named(&turn.room_id).map(|room| TurnPlace::Row {
            room,
            turn: Box::new(turn),
        }));
    }
    let crate::vault::LiveEntityRow::Live {
        entity_type: crate::registry::ENTITY_TYPE_TURN,
        body,
    } = crate::vault::live_entity_row_in_txn(store, txn, &id)?
    else {
        return Ok(None);
    };
    let Some(room) = crate::conversation_dag::room_turn_owner(store, txn, &id)
        .ok()
        .flatten()
    else {
        return Ok(None);
    };
    Ok(match thread_binding(&body) {
        Ok(None) => Some(TurnPlace::Dag { room, root: None }),
        Ok(Some(binding)) if binding.room == room => Some(TurnPlace::Dag {
            room,
            root: Some(binding.root),
        }),
        _ => None,
    })
}

/// The side rows this vault holds that ride entity `id` of type
/// `entity_type` (FIX 1794): a room's host pin, handles and room-wide facts,
/// or a room turn's claim and response and the facts of the thread it roots,
/// with the Ready joins and current offer cards of the room or that thread.
/// A turn is placed by [`turn_place_in`], a DAG TURN of an ordinary room too
/// (FIX 3094). A row that does not decode is left out.
pub(crate) fn replicated_side_rows_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    entity_type: u8,
) -> Result<Vec<RoomSideRow>> {
    let store = &vault.store;
    let mut rows = Vec::new();
    let (room, branch, roots) = match entity_type {
        crate::registry::ENTITY_TYPE_CONVERSATION => {
            if let Some(pin) = super::hosting::HOST_PINS.get_lenient(store, txn, &id)? {
                rows.push(RoomSideRow::HostPin { room: id, pin });
            }
            for ((room, handle), actor) in HANDLES.iter_from(store, txn, id.as_bytes())?.flatten() {
                rows.push(RoomSideRow::Handle {
                    room,
                    handle,
                    actor,
                });
            }
            (id, None, true)
        }
        crate::registry::ENTITY_TYPE_TURN => {
            let Some(place) = turn_place_in(vault, txn, id)? else {
                return Ok(rows);
            };
            let room = place.room();
            if let Some(claim) = CLAIMS.get_lenient(store, txn, &id)? {
                rows.push(RoomSideRow::Claim { claim });
            }
            if let Some(response) = RESPONSE.get_lenient(store, txn, &id)?
                && let Some(spoken) = TURNS.get_lenient(store, txn, &response)?
                && let Some(actor) = named(&spoken.actor)
            {
                rows.push(RoomSideRow::Response {
                    room,
                    parent: id,
                    response,
                    actor,
                    at: spoken.at,
                });
            }
            (room, Some(id), place.roots(id))
        }
        _ => return Ok(rows),
    };
    let prefix = participation::place_prefix(room, branch);
    let mut subjects = Vec::new();
    for (key, fact) in participation::FACTS
        .iter_from(store, txn, &prefix)?
        .flatten()
    {
        // An erased subject's fact names no one and rides no window (FIX 4228).
        let FactSubject::Live(subject) = key.subject else {
            continue;
        };
        if !subjects.contains(&subject) {
            subjects.push(subject);
        }
        rows.push(RoomSideRow::Participation {
            room,
            branch,
            subject,
            at: fact.at,
            join_ref: fact.join_ref,
            cause: fact.cause,
        });
    }
    // Joins and cards name a thread by its root.
    if roots {
        shared_rows_in(vault, txn, room, branch, &subjects, &mut rows)?;
    }
    Ok(rows)
}

/// The Ready joins and current offer cards of `room` itself, or of its
/// thread `branch`, with the join each card filed (FIX 1794). A thread's
/// Ready joins are looked up for the `subjects` its facts name, so a room of
/// many threads is not read whole for each. A held or refused join, and a
/// replaced card, ride when the door that wrote them mirrors them.
fn shared_rows_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    subjects: &[JoinSubject],
    rows: &mut Vec<RoomSideRow>,
) -> Result<()> {
    let store = &vault.store;
    let mut joins = BTreeSet::new();
    match branch {
        None => {
            for (key, join_ref) in READY
                .iter_from(store, txn, format!("{}/", room.to_hex()).as_bytes())?
                .flatten()
            {
                if key.ends_with("/-") {
                    joins.insert(join_ref);
                }
            }
        }
        Some(branch) => {
            for subject in subjects {
                joins.extend(READY.get_lenient(
                    store,
                    txn,
                    &ready_key(room, subject, Some(branch)),
                )?);
            }
        }
    }
    let place = branch.map_or_else(|| "-".to_owned(), |branch| branch.to_hex());
    for (_, offer_id) in OFFER_CURRENT
        .iter_from(store, txn, format!("{}/{place}/", room.to_hex()).as_bytes())?
        .flatten()
    {
        if let Some(offer) = OFFERS.get_lenient(store, txn, &offer_id)? {
            joins.insert(offer.card.join_ref.clone());
            rows.push(RoomSideRow::Offer { offer });
        }
    }
    for join_ref in joins {
        if let Some(receipt) = JOINS.get_lenient(store, txn, &join_ref)? {
            rows.push(RoomSideRow::Join { receipt });
        }
    }
    Ok(())
}

/// This vault's join receipt under `reference`, or with `offer` its offer
/// card under that id and the join the card filed, as side rows (FIX 1794).
/// Empty when it holds none.
pub(crate) fn replicated_shared_rows_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    offer: bool,
    reference: &str,
) -> Result<Vec<RoomSideRow>> {
    let store = &vault.store;
    let mut rows = Vec::new();
    let mut join = (!offer).then(|| reference.to_owned());
    if offer && let Some(stored) = OFFERS.get_lenient(store, txn, &reference.to_owned())? {
        join = Some(stored.card.join_ref.clone());
        rows.push(RoomSideRow::Offer { offer: stored });
    }
    if let Some(join) = join
        && let Some(receipt) = JOINS.get_lenient(store, txn, &join)?
    {
        rows.push(RoomSideRow::Join { receipt });
    }
    Ok(rows)
}

/// What merging a carried side row did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SideMerge {
    /// The row this vault holds changed.
    Written,
    /// This vault holds what the row carries.
    Held,
    /// Two rows met where one stands: the one that stands is held, and the
    /// other stays in the window and is logged.
    Conflict,
    /// The row is left out, for the reason given.
    Refused(TurnMergeRefusal),
}

/// Why this vault refuses the side rows of `room`, or of its thread
/// `branch`: erase wins over every side row.
fn side_refusal_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
) -> Result<Option<TurnMergeRefusal>> {
    if crate::ports::removed_in_txn(&vault.store, txn, &room)? {
        return Ok(Some(TurnMergeRefusal::RoomDeleted));
    }
    if crate::ports::EntityStoreRead::port_entity_record(&vault.store, txn, &room)?.is_none() {
        return Ok(Some(TurnMergeRefusal::RoomMissing));
    }
    if let Some(branch) = branch
        && crate::ports::removed_in_txn(&vault.store, txn, &branch)?
    {
        return Ok(Some(TurnMergeRefusal::ThreadDeleted));
    }
    Ok(None)
}

/// Merges a side row another machine of this vault carried (FIX 1794). A
/// host pin or handle is the window's cell, whose latest carrier write by
/// Loro order the window chose, and is written as carried. A claim is
/// written once: the lowest `(at, receipt_ref)` stands. A participation fact
/// is appended once under its key: a divergent payload keeps the earlier
/// `(at, cause)`. A response is settled with its rivals by
/// [`merge_replicated_responses_in_txn`], and a join or offer card merged by
/// [`merge_replicated_shared_row_in_txn`]. A row of a room this vault
/// deleted, or holds no record of, or a fact of a thread it erased, is
/// refused before anything is written.
pub(crate) fn merge_replicated_side_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &RoomSideRow,
) -> Result<SideMerge> {
    let Some((room, branch)) = row.place().filter(|_| row.well_formed()) else {
        return Ok(SideMerge::Refused(TurnMergeRefusal::InvalidIds));
    };
    if let Some(refusal) = side_refusal_in(vault, txn, room, branch)? {
        return Ok(SideMerge::Refused(refusal));
    }
    let store = &vault.store;
    match row {
        RoomSideRow::HostPin { room, pin } => {
            // FIX 4227: the pin as this vault knows who it names.
            let Some(pin) = carrier_erase::carried_pin(vault, txn, pin)? else {
                return Ok(SideMerge::Refused(TurnMergeRefusal::ActorErased));
            };
            if super::hosting::HOST_PINS
                .get_lenient(store, txn, room)?
                .is_some_and(|held| held == pin)
            {
                return Ok(SideMerge::Held);
            }
            super::hosting::HOST_PINS.put(store, txn, room, &pin)?;
        }
        RoomSideRow::Handle {
            room,
            handle,
            actor,
        } => {
            let key = (*room, handle.clone());
            if HANDLES.get_lenient(store, txn, &key)? == Some(*actor) {
                return Ok(SideMerge::Held);
            }
            HANDLES.put(store, txn, &key, actor)?;
        }
        RoomSideRow::Claim { claim } => {
            let turn = EntityId::from_hex(&claim.turn_id)?;
            if TURNS
                .get_lenient(store, txn, &turn)?
                .is_some_and(|held| held.room_id != claim.room_id)
            {
                return Ok(SideMerge::Refused(TurnMergeRefusal::FixedFieldsConflict));
            }
            if let Some(held) = CLAIMS.get_lenient(store, txn, &turn)? {
                if held == *claim {
                    return Ok(SideMerge::Held);
                }
                if (held.at, &held.receipt_ref) > (claim.at, &claim.receipt_ref) {
                    CLAIMS.put(store, txn, &turn, claim)?;
                }
                return Ok(SideMerge::Conflict);
            }
            CLAIMS.put(store, txn, &turn, claim)?;
        }
        RoomSideRow::Participation {
            room,
            branch,
            subject,
            at,
            join_ref,
            cause,
        } => {
            let key = participation::FactKey {
                room: *room,
                branch: branch.map_or([0; 16], |branch| *branch.as_bytes()),
                subject: FactSubject::Live(*subject),
                cause: (cause.kind(), cause.key_id()),
            };
            // FIX 4228: an erased subject's fact lands under no one's key.
            let Some(key) = carrier_erase::carried_fact_key_in_txn(vault, txn, key)? else {
                return Ok(SideMerge::Refused(TurnMergeRefusal::ActorErased));
            };
            let carried = participation::Fact {
                at: *at,
                join_ref: join_ref.clone(),
                cause: cause.clone(),
            };
            if let Some(held) = participation::FACTS.get_lenient(store, txn, &key)? {
                if held == carried {
                    return Ok(SideMerge::Held);
                }
                if fact_order(&held) > fact_order(&carried) {
                    participation::FACTS.put(store, txn, &key, &carried)?;
                }
                return Ok(SideMerge::Conflict);
            }
            participation::FACTS.put(store, txn, &key, &carried)?;
        }
        RoomSideRow::Response { parent, .. } => {
            return merge_replicated_responses_in_txn(
                vault,
                txn,
                *parent,
                std::slice::from_ref(row),
            );
        }
        RoomSideRow::Join { .. } | RoomSideRow::Offer { .. } => {
            return Ok(merge_shared_in_txn(vault, txn, row)?.0);
        }
    }
    Ok(SideMerge::Written)
}

/// Clears room `room`'s host pin, or its platform handle `handle`, whose
/// cell the window dropped (FIX 1794): a clear another machine made, or the
/// scrub of a room erased there.
pub(crate) fn clear_replicated_side_cell_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    handle: Option<&str>,
) -> Result<SideMerge> {
    let cleared = match handle {
        None => super::hosting::HOST_PINS.delete(&vault.store, txn, &room)?,
        Some(handle) => HANDLES.delete(&vault.store, txn, &(room, handle.to_owned()))?,
    };
    Ok(if cleared {
        SideMerge::Written
    } else {
        SideMerge::Held
    })
}

/// The entities whose windows take the side rows a door wrote for room turn
/// `turn` (FIX 1794), each with its type: its room, the turn, the turn it
/// answers and the root of its thread. A DAG TURN of an ordinary room is
/// placed as [`turn_place_in`] places it, and answers no claimed turn (FIX
/// 3094). None for a turn this vault places in no room.
pub(crate) fn replicated_side_carriers_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
) -> Result<Vec<(EntityId, u8)>> {
    let Some(place) = turn_place_in(vault, txn, turn)? else {
        return Ok(Vec::new());
    };
    let mut carriers = vec![
        (place.room(), crate::registry::ENTITY_TYPE_CONVERSATION),
        (turn, crate::registry::ENTITY_TYPE_TURN),
    ];
    let (parent, root) = match &place {
        TurnPlace::Row { turn: row, .. } => (
            row.reply_to.as_deref().and_then(named),
            participation::turn_root_in_txn(vault, txn, row)
                .ok()
                .flatten(),
        ),
        TurnPlace::Dag { root, .. } => (None, *root),
    };
    for id in [parent, root].into_iter().flatten() {
        if !carriers.iter().any(|(held, _)| *held == id) {
            carriers.push((id, crate::registry::ENTITY_TYPE_TURN));
        }
    }
    Ok(carriers)
}
