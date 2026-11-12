//! The one-time room-row backfill at writable open (THREAD-TASK-EVERY-ROOM
//! P2, Engine ruling 12 Nov 16:01). Since P1 every TURN of every room keeps
//! its room row in the write that lands it. A vault older than that holds
//! TURNs with no row: the native DAG appends of every room but a project's
//! home room, a home room's native trunk turns, and the witness turns of an
//! ordinary room. This pass rows each of them once, room by room, from what
//! the TURN itself recorded, so every room reader can read rows alone.
//!
//! - One grouped write per room. The room's marker is written last in that
//!   write, so a crash resumes at the first unmarked room.
//! - A row that is present is never read for repair or rewritten.
//! - Recorded facts only. The row names the writer the TURN recorded, every
//!   recipient its DAG record named (Q1 = A), its MESSAGEs and its DAG
//!   topology. It stages no wake, files no Addressed fact, claim, join or
//!   offer engagement, and mints no quote pin.
//! - No row for an erased TURN, or a TURN that recorded no writer, such as
//!   an imported one (Q2 = A). A home room's witness TURN with no row is
//!   one the home witness never admitted, so it is left out as well. A TURN
//!   whose stored body or DAG parent does not decode gets no row either, and
//!   the open goes on. Each skip is counted by kind.
//! - A room with a waiting erase is skipped with no marker, and a later
//!   open retries it (Q3 = A). An archived vault is left as it is.
//!
//! Entry: [`backfill_room_turns_on_open`].

use super::*;
use crate::conversation_dag::{addressing, retained_parent};
use crate::edge::EdgeKind;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use std::collections::BTreeMap;

/// The version of the backfill each room completed. Key: id16 (room).
pub(super) const TURN_BACKFILL: SideTable<EntityId, u64, Raw> =
    SideTable::new(&side_table::ROOMS_TURN_BACKFILL);

/// The backfill version a room's marker holds once the pass rowed it.
pub(crate) const ROOM_TURN_BACKFILL_VERSION: u64 = 1;

/// What one backfill pass did, room by room and TURN by TURN.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RoomTurnBackfill {
    /// Rooms this pass marked complete.
    pub(crate) rooms_completed: u64,
    /// Rooms left unmarked for a later open: a waiting erase holds them.
    pub(crate) rooms_deferred: u64,
    /// Rows this pass wrote.
    pub(crate) turns_written: u64,
    /// TURNs that already kept a row.
    pub(crate) turns_present: u64,
    /// Erased TURNs: no row.
    pub(crate) skipped_erased: u64,
    /// TURNs that recorded no writer, such as an imported one: no row.
    pub(crate) skipped_no_writer: u64,
    /// Thread TURNs whose binding names no anchor, or that keep no DAG
    /// parent: no row, as the native writer keeps none for them.
    pub(crate) skipped_unbound: u64,
    /// A home room's witness TURNs with no row: no row.
    pub(crate) skipped_home_witness: u64,
    /// TURNs whose body or DAG parent does not decode: no row.
    pub(crate) skipped_undecodable: u64,
}

impl RoomTurnBackfill {
    fn add(&mut self, room: &Self) {
        self.rooms_completed += room.rooms_completed;
        self.rooms_deferred += room.rooms_deferred;
        self.turns_written += room.turns_written;
        self.turns_present += room.turns_present;
        self.skipped_erased += room.skipped_erased;
        self.skipped_no_writer += room.skipped_no_writer;
        self.skipped_unbound += room.skipped_unbound;
        self.skipped_home_witness += room.skipped_home_witness;
        self.skipped_undecodable += room.skipped_undecodable;
    }
}

/// Why one TURN gets no row.
enum Skip {
    NoWriter,
    Unbound,
    HomeWitness,
    Undecodable,
}

/// Rows every TURN of every room that has none, once per room, at a
/// writable open, before any reader holds the vault. A vault whose rooms all
/// carry the marker pays one read per room and writes nothing.
pub(crate) fn backfill_room_turns_on_open(vault: &Vault) -> Result<RoomTurnBackfill> {
    let started = std::time::Instant::now();
    let mut report = RoomTurnBackfill::default();
    let due = {
        let txn = vault.store.env.read_txn()?;
        if vault.store.archived_in_txn(&txn)? {
            return Ok(report);
        }
        let mut due = Vec::new();
        for row in vault
            .store
            .port_entity_ids_by_type(&txn, ENTITY_TYPE_CONVERSATION, None)?
        {
            let room = row?;
            if TURN_BACKFILL.get(&vault.store, &txn, &room)? == Some(ROOM_TURN_BACKFILL_VERSION)
                || !live_room_in(vault, &txn, room)?
            {
                continue;
            }
            // A room with a waiting erase is retried on a later open; no
            // write is opened for it now.
            if crate::store::legal_hold::pending_erase_in_txn(&vault.store, &txn, &room)?.is_some()
            {
                report.rooms_deferred += 1;
                continue;
            }
            due.push(room);
        }
        due
    };
    for room in due {
        let one = vault.with_write_txn_grouped(|txn| backfill_room_in_txn(vault, txn, room))?;
        report.add(&one);
    }
    if report.rooms_completed + report.rooms_deferred > 0 {
        tracing::info!(
            rooms_completed = report.rooms_completed,
            rooms_deferred = report.rooms_deferred,
            turns_written = report.turns_written,
            turns_present = report.turns_present,
            skipped_erased = report.skipped_erased,
            skipped_no_writer = report.skipped_no_writer,
            skipped_unbound = report.skipped_unbound,
            skipped_home_witness = report.skipped_home_witness,
            skipped_undecodable = report.skipped_undecodable,
            ms = started.elapsed().as_millis() as u64,
            "room turn backfill"
        );
    }
    Ok(report)
}

/// Rows each TURN of `room` that keeps none, then marks `room`, in `txn`.
/// A room that is gone is left unmarked: it has no TURN to row.
fn backfill_room_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
) -> Result<RoomTurnBackfill> {
    let mut report = RoomTurnBackfill::default();
    let store = &vault.store;
    if TURN_BACKFILL.get(store, txn, &room)? == Some(ROOM_TURN_BACKFILL_VERSION)
        || !live_room_in(vault, txn, room)?
    {
        return Ok(report);
    }
    if crate::store::legal_hold::pending_erase_in_txn(store, txn, &room)?.is_some() {
        report.rooms_deferred = 1;
        return Ok(report);
    }
    let home = super::super::project::ROOM_PROJECT.contains(store, txn, &room)?;
    let mut turns = Vec::new();
    for row in store.port_edges(txn, &room, EdgeDirection::In, Some(EdgeKind::ChildOf), None)? {
        turns.push(row?.target);
    }
    for id in turns {
        if TURNS.contains(store, txn, &id)? {
            report.turns_present += 1;
            continue;
        }
        let body = match live_entity_row_in_txn(store, txn, &id)? {
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_TURN,
                body,
            } => body,
            LiveEntityRow::DeletedShell => {
                if store
                    .port_entity_record(txn, &id)?
                    .is_some_and(|row| row.entity_type == ENTITY_TYPE_TURN)
                {
                    report.skipped_erased += 1;
                }
                continue;
            }
            _ => continue,
        };
        match recorded_turn_in(vault, txn, room, id, &body, home)? {
            Ok(turn) => {
                super::turn_record::put_room_turn_projection_in_txn(vault, txn, &turn)?;
                report.turns_written += 1;
            }
            Err(Skip::NoWriter) => report.skipped_no_writer += 1,
            Err(Skip::Unbound) => report.skipped_unbound += 1,
            Err(Skip::HomeWitness) => report.skipped_home_witness += 1,
            Err(Skip::Undecodable) => report.skipped_undecodable += 1,
        }
    }
    TURN_BACKFILL.put(store, txn, &room, &ROOM_TURN_BACKFILL_VERSION)?;
    report.rooms_completed = 1;
    Ok(report)
}

/// The row the TURN `id` of `room`, whose live body is `body`, recorded:
/// the fields its own write would have given it, read back from that write.
/// A DAG record answers its `Parent` inside the thread its binding names,
/// or nothing on the trunk, and names every recipient it recorded. A
/// witness turn of an ordinary room is a trunk turn naming no one, as the
/// witness rows it. Neither holds a TASK, a conversion or a row quote: each
/// of those needs a row its write found first.
fn recorded_turn_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    id: EntityId,
    body: &[u8],
    home: bool,
) -> Result<std::result::Result<RoomTurn, Skip>> {
    let store = &vault.store;
    let (actor, addressed, reply_to, thread_of) = match recorded_shape(vault, txn, id, body, home) {
        Ok(Ok(shape)) => shape,
        Ok(Err(skip)) => return Ok(Err(skip)),
        Err(error) => {
            tracing::warn!(
                turn = %id.to_hex(),
                room = %room.to_hex(),
                %error,
                "room turn backfill: the TURN does not decode; it keeps no row"
            );
            return Ok(Err(Skip::Undecodable));
        }
    };
    let at = store
        .port_entity_record(txn, &id)?
        .ok_or(Error::EntityNotFound)?
        .occurred
        .start;
    Ok(Ok(RoomTurn {
        turn_id: id.to_hex(),
        room_id: room.to_hex(),
        actor: actor.to_hex(),
        addressed_agents: addressed,
        message_ids: recorded_messages_in(vault, txn, id)?,
        reply_to,
        thread_of,
        at,
        task_ids: Vec::new(),
        converted_project: None,
        quotes: BTreeMap::new(),
    }))
}

/// The writer, recipients, `reply_to` and `thread_of` the TURN `id`, whose
/// live body is `body`, recorded. An error is a body or DAG parent that
/// does not decode.
fn recorded_shape(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    body: &[u8],
    home: bool,
) -> Result<std::result::Result<RecordedShape, Skip>> {
    let Some(actor) = crate::conversation::record_author(body)? else {
        return Ok(Err(Skip::NoWriter));
    };
    let Some((_, recipients)) = addressing(body)? else {
        if home {
            return Ok(Err(Skip::HomeWitness));
        }
        return Ok(Ok((actor, BTreeSet::new(), None, None)));
    };
    let addressed = recipients.iter().map(EntityId::to_hex).collect();
    let Some(binding) = super::audience::thread_binding(body)? else {
        return Ok(Ok((actor, addressed, None, None)));
    };
    let (Some(parent), Some(anchor)) = (retained_parent(&vault.store, txn, &id)?, binding.anchor)
    else {
        return Ok(Err(Skip::Unbound));
    };
    Ok(Ok((
        actor,
        addressed,
        Some(parent.to_hex()),
        Some(anchor.to_hex()),
    )))
}

/// A TURN's recorded writer, recipients (hex), `reply_to` and `thread_of`.
type RecordedShape = (EntityId, BTreeSet<String>, Option<String>, Option<String>);

/// Whether `room` is a live Conversation.
fn live_room_in(vault: &Vault, txn: &heed::RoTxn<'_>, room: EntityId) -> Result<bool> {
    Ok(matches!(
        live_entity_row_in_txn(&vault.store, txn, &room)?,
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_CONVERSATION,
            ..
        }
    ))
}

/// The live MESSAGEs of `turn`, in their recorded order (ties by id). An
/// erased MESSAGE is not listed.
fn recorded_messages_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
) -> Result<Vec<String>> {
    let mut messages = Vec::new();
    for id in vault.turn_message_ids_in(txn, &turn)? {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_MESSAGE,
            body,
        } = live_entity_row_in_txn(&vault.store, txn, &id)?
        else {
            continue;
        };
        messages.push((message_order(&body), id));
    }
    messages.sort_unstable();
    Ok(messages.into_iter().map(|(_, id)| id.to_hex()).collect())
}

/// A MESSAGE body's recorded `order`, `u64::MAX` when it keeps none.
fn message_order(body: &[u8]) -> u64 {
    let mut bytes = body;
    let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut bytes) else {
        return u64::MAX;
    };
    fields
        .iter()
        .find(|(key, _)| key.as_str() == Some("order"))
        .and_then(|(_, value)| value.as_u64())
        .unwrap_or(u64::MAX)
}

/// The doors the backfill's integration test reads and strips rows through
/// (`tests/room_turn_backfill.rs`), re-exposed by `crate::test_doors`.
/// Compiled only under the test-support cfg.
#[cfg(oneiron_test_support)]
pub(crate) mod doors {
    use super::*;

    pub(crate) use super::ROOM_TURN_BACKFILL_VERSION;

    /// `(at, turn)` of every HISTORY row, `(at, turn)` of every HEADS row
    /// and `(anchor, turn)` of every THREAD_CHILDREN row of a room, each in
    /// key order.
    pub(crate) type RoomIndexRows = (
        Vec<(u64, EntityId)>,
        Vec<(u64, EntityId)>,
        Vec<(EntityId, EntityId)>,
    );

    /// Removes the room row, its HISTORY row, its HEADS or THREAD_CHILDREN
    /// row, and the room's marker, for every rowed TURN of `room` not in
    /// `keep`: the state a vault older than P1 held. Returns the count.
    pub(crate) fn strip_room_turn_rows(
        vault: &Vault,
        room: EntityId,
        keep: &[EntityId],
    ) -> Result<u64> {
        vault.with_write_txn_grouped(|txn| {
            let store = &vault.store;
            let rows: Vec<((EntityId, u64, EntityId), EntityId)> = HISTORY
                .iter_from(store, txn, room.as_bytes())?
                .collect::<Result<Vec<_>>>()?;
            let mut stripped = 0;
            for (key, turn) in rows {
                if keep.contains(&turn) {
                    continue;
                }
                let row = TURNS
                    .get(store, txn, &turn)?
                    .ok_or(Error::CorruptedIndex("room turn"))?;
                match row.thread_of {
                    Some(anchor) => {
                        let anchor = EntityId::from_hex(&anchor)?;
                        THREAD_CHILDREN.delete(store, txn, &(room, anchor, turn))?;
                    }
                    None => {
                        HEADS.delete(store, txn, &(room, row.at, turn))?;
                    }
                }
                HISTORY.delete(store, txn, &key)?;
                TURNS.delete(store, txn, &turn)?;
                stripped += 1;
            }
            TURN_BACKFILL.delete(store, txn, &room)?;
            Ok(stripped)
        })
    }

    /// Every room row of `room`, raw, in HISTORY order; no reader filter.
    pub(crate) fn room_turn_rows(vault: &Vault, room: EntityId) -> Result<Vec<RoomTurn>> {
        let txn = vault.store.env.read_txn()?;
        let mut rows = Vec::new();
        for row in HISTORY.iter_from(&vault.store, &txn, room.as_bytes())? {
            let (_, turn) = row?;
            rows.push(
                TURNS
                    .get(&vault.store, &txn, &turn)?
                    .ok_or(Error::CorruptedIndex("room turn"))?,
            );
        }
        Ok(rows)
    }

    /// The room row of `turn`, raw.
    pub(crate) fn room_turn_row(vault: &Vault, turn: EntityId) -> Result<Option<RoomTurn>> {
        let txn = vault.store.env.read_txn()?;
        TURNS.get(&vault.store, &txn, &turn)
    }

    /// Puts `row` as the room row of its TURN, with no index change.
    pub(crate) fn put_room_turn_row(vault: &Vault, row: &RoomTurn) -> Result<()> {
        let turn = EntityId::from_hex(&row.turn_id)?;
        vault.with_write_txn_grouped(|txn| TURNS.put(&vault.store, txn, &turn, row))
    }

    /// `room`'s HISTORY, HEADS and THREAD_CHILDREN rows.
    pub(crate) fn room_index_rows(vault: &Vault, room: EntityId) -> Result<RoomIndexRows> {
        let txn = vault.store.env.read_txn()?;
        let store = &vault.store;
        let mut rows = RoomIndexRows::default();
        for row in HISTORY.iter_from(store, &txn, room.as_bytes())? {
            let ((_, at, turn), _) = row?;
            rows.0.push((at, turn));
        }
        for row in HEADS.iter_from(store, &txn, room.as_bytes())? {
            let ((_, at, turn), _) = row?;
            rows.1.push((at, turn));
        }
        for row in THREAD_CHILDREN.iter_from(store, &txn, room.as_bytes())? {
            let ((_, anchor, turn), _) = row?;
            rows.2.push((anchor, turn));
        }
        Ok(rows)
    }

    /// `room`'s backfill marker.
    pub(crate) fn room_turn_backfill_marker(vault: &Vault, room: EntityId) -> Result<Option<u64>> {
        let txn = vault.store.env.read_txn()?;
        TURN_BACKFILL.get(&vault.store, &txn, &room)
    }

    /// Every room wake attempt row, in any state.
    pub(crate) fn room_wake_attempt_rows(vault: &Vault) -> Result<u64> {
        let txn = vault.store.env.read_txn()?;
        let rows = crate::attempt_queue::AttemptQueue::new(vault)
            .kind_working_rows_in_txn(&txn, super::super::wake::ROOM_WAKE_ATTEMPT_KIND)?;
        Ok(rows.len() as u64)
    }
}
