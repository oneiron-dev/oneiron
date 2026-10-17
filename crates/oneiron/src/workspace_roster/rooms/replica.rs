//! OF-522: a room's turn rows on the owner's other machines. Each turn row,
//! with its thread-task bindings and conversion mark, rides the window its
//! TURN rides (`crate::sync::rooms`). A machine that takes one merges it here
//! as the witness door's append does, and indexes the room's history from it.
use super::*;

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
/// addressing, links, quote, time and conversion, and takes the carried
/// messages and bound tasks it lacks; a carried row that names other fixed
/// fields is refused. A row whose room this vault deleted, or holds no
/// record of, is refused before anything is written, so no turn or history
/// row dangles from a room that is gone (OF-522).
pub(crate) fn merge_replicated_turn_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    carried: RoomTurn,
) -> Result<TurnMerge> {
    let named = |hex: &str| EntityId::from_hex(hex).is_ok_and(|id| id.to_hex() == hex);
    if !named(&carried.turn_id)
        || !named(&carried.room_id)
        || !named(&carried.actor)
        || carried.reply_to.as_deref().is_some_and(|id| !named(id))
        || carried.thread_of.as_deref().is_some_and(|id| !named(id))
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
    let id = EntityId::from_hex(&carried.turn_id)?;
    let merged = match TURNS.get(&vault.store, txn, &id)? {
        None => carried,
        Some(held) => {
            if held.room_id != carried.room_id
                || held.actor != carried.actor
                || held.addressed_agents != carried.addressed_agents
                || held.reply_to != carried.reply_to
                || held.thread_of != carried.thread_of
                || held.quote != carried.quote
            {
                return Ok(TurnMerge::Refused(TurnMergeRefusal::FixedFieldsConflict));
            }
            let mut merged = held.clone();
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
}

impl RoomSideRow {
    /// The room the row belongs to, and the thread root a fact names; `None`
    /// when the row names an id that does not parse.
    pub(crate) fn place(&self) -> Option<(EntityId, Option<EntityId>)> {
        match self {
            Self::HostPin { room, .. }
            | Self::Handle { room, .. }
            | Self::Response { room, .. } => Some((*room, None)),
            Self::Claim { claim } => named(&claim.room_id).map(|room| (room, None)),
            Self::Participation { room, branch, .. } => Some((*room, *branch)),
        }
    }

    /// Whether the row keeps its table's shape: ids that parse, and a handle
    /// the bind door would take.
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
            _ => true,
        }
    }
}

/// `hex` as an id, when it is one's canonical spelling.
fn named(hex: &str) -> Option<EntityId> {
    EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
}

/// The side rows this vault holds that ride entity `id` of type
/// `entity_type` (FIX 1794): a room's host pin, handles and room-wide facts,
/// or a room turn's claim and response and the facts of the thread it roots.
/// A row that does not decode is left out.
pub(crate) fn replicated_side_rows_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    entity_type: u8,
) -> Result<Vec<RoomSideRow>> {
    let store = &vault.store;
    let mut rows = Vec::new();
    let (room, branch) = match entity_type {
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
            (id, None)
        }
        crate::registry::ENTITY_TYPE_TURN => {
            let Some(turn) = TURNS.get_lenient(store, txn, &id)? else {
                return Ok(rows);
            };
            let Some(room) = named(&turn.room_id) else {
                return Ok(rows);
            };
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
            (room, Some(id))
        }
        _ => return Ok(rows),
    };
    let prefix = participation::place_prefix(room, branch);
    for (key, fact) in participation::FACTS
        .iter_from(store, txn, &prefix)?
        .flatten()
    {
        rows.push(RoomSideRow::Participation {
            room,
            branch,
            subject: key.subject,
            at: fact.at,
            join_ref: fact.join_ref,
            cause: fact.cause,
        });
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
/// [`merge_replicated_responses_in_txn`]. A row of a room this vault
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
            if super::hosting::HOST_PINS
                .get_lenient(store, txn, room)?
                .is_some_and(|held| held == *pin)
            {
                return Ok(SideMerge::Held);
            }
            super::hosting::HOST_PINS.put(store, txn, room, pin)?;
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
                subject: *subject,
                cause: (cause.kind(), cause.key_id()),
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
    }
    Ok(SideMerge::Written)
}

/// The order two payloads under one fact key settle by: the earlier
/// `(at, cause)` stands, and the receipt it stood on breaks a tie.
fn fact_order(fact: &participation::Fact) -> (u64, Vec<u8>, Option<String>) {
    (
        fact.at,
        serde_json::to_vec(&fact.cause).unwrap_or_default(),
        fact.join_ref.clone(),
    )
}

/// Settles which turn answers claimed turn `parent` (FIX 1794), from the
/// response this vault holds and each carried one: the response whose
/// speaker holds the turn's claim stands, and among those, or when none
/// does, the earliest `(at, response)`. A response that loses keeps its
/// TURN, which was spoken; it loses only the slot, and is logged.
pub(crate) fn merge_replicated_responses_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    parent: EntityId,
    carried: &[RoomSideRow],
) -> Result<SideMerge> {
    let store = &vault.store;
    let parent_room = TURNS
        .get_lenient(store, txn, &parent)?
        .map(|turn| turn.room_id);
    let mut candidates: Vec<(EntityId, Option<EntityId>, u64)> = Vec::new();
    let mut refused = None;
    for row in carried {
        let RoomSideRow::Response {
            room,
            parent: answered,
            response,
            actor,
            at,
        } = row
        else {
            continue;
        };
        if *answered != parent
            || parent_room
                .as_ref()
                .is_some_and(|held| *held != room.to_hex())
        {
            refused = Some(TurnMergeRefusal::FixedFieldsConflict);
            continue;
        }
        if let Some(refusal) = side_refusal_in(vault, txn, *room, None)? {
            refused = Some(refusal);
            continue;
        }
        if !candidates.iter().any(|(id, ..)| id == response) {
            candidates.push((*response, Some(*actor), *at));
        }
    }
    if candidates.is_empty() {
        return Ok(refused.map_or(SideMerge::Held, SideMerge::Refused));
    }
    let held = RESPONSE.get_lenient(store, txn, &parent)?;
    if let Some(held) = held
        && !candidates.iter().any(|(id, ..)| *id == held)
    {
        let spoken = TURNS.get_lenient(store, txn, &held)?;
        candidates.push((
            held,
            spoken.as_ref().and_then(|turn| named(&turn.actor)),
            spoken.map_or(u64::MAX, |turn| turn.at),
        ));
    }
    let claimant = CLAIMS
        .get_lenient(store, txn, &parent)?
        .and_then(|claim| named(&claim.actor));
    let Some(&(winner, ..)) = candidates.iter().min_by_key(|(response, actor, at)| {
        (claimant.is_some() && *actor != claimant, *at, *response)
    }) else {
        return Ok(SideMerge::Held);
    };
    if held != Some(winner) {
        RESPONSE.put(store, txn, &parent, &winner)?;
    }
    Ok(if candidates.len() > 1 {
        SideMerge::Conflict
    } else if held == Some(winner) {
        SideMerge::Held
    } else {
        SideMerge::Written
    })
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
/// answers and the root of its thread. None for a turn this vault holds no
/// room row of.
pub(crate) fn replicated_side_carriers_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
) -> Result<Vec<(EntityId, u8)>> {
    let Some(row) = TURNS.get_lenient(&vault.store, txn, &turn)? else {
        return Ok(Vec::new());
    };
    let Some(room) = named(&row.room_id) else {
        return Ok(Vec::new());
    };
    let mut carriers = vec![
        (room, crate::registry::ENTITY_TYPE_CONVERSATION),
        (turn, crate::registry::ENTITY_TYPE_TURN),
    ];
    let parent = row.reply_to.as_deref().and_then(named);
    let root = participation::turn_root_in_txn(vault, txn, &row)
        .ok()
        .flatten();
    for id in [parent, root].into_iter().flatten() {
        if !carriers.iter().any(|(held, _)| *held == id) {
            carriers.push((id, crate::registry::ENTITY_TYPE_TURN));
        }
    }
    Ok(carriers)
}
