//! A live append's participation (OF-529): the thread it lands in, and the
//! room's participation gate its writer passes before the record is written.

use super::AppendRecord;
use super::graph;
use super::topology::RecordKind;
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::ENTITY_TYPE_TURN;
use crate::store::Store;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::workspace_roster::{Admitted, JoinCause, RoomTurn};
use crate::{EntityId, Vault};
use heed::RoTxn;
use std::collections::{BTreeMap, BTreeSet};

/// The thread a live append lands in: the root of its chain, the first
/// thread record walked up `Parent`, never the moving tip. A thread append
/// whose parent is a trunk record is the root itself. `None` for a trunk
/// append.
fn thread_root_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    parent: Option<EntityId>,
    record: EntityId,
    thread: bool,
) -> Result<Option<EntityId>> {
    if !thread {
        return Ok(None);
    }
    let mut root = record;
    let mut cursor = parent;
    let mut steps = 0;
    while let Some(id) = cursor {
        if !graph::is_thread_record(store, txn, &id)? {
            break;
        }
        steps += 1;
        if steps > MAX_ANCESTOR_DEPTH {
            return Err(Error::IndexOverflow("conversation_dag_walk"));
        }
        root = id;
        cursor = graph::parent(store, txn, &id)?;
    }
    Ok(Some(root))
}

/// Admits the writer of a live authored append, `record`, answering
/// `reply_to`, before it is written: a person with room standing writes on,
/// and a person new to an ordinary room joins it by this write. An agent
/// joins by no write: it stands there and speaks only when it is addressed
/// on the record it answers, holds that thread's task, or lands an accepted
/// offer (ARCH-0006a, ruled 2026-09-23). The caller records the fact once
/// the record is written.
pub(super) fn admit_append_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: &AppendRecord,
    record: EntityId,
    thread: bool,
    reply_to: Option<EntityId>,
) -> Result<Admitted> {
    let branch = thread_root_in_txn(&vault.store, txn, input.parent, record, thread)?;
    crate::workspace_roster::admit_participation_in_txn(
        vault,
        txn,
        input.conversation,
        branch,
        input.actor,
        JoinCause::Wrote { turn: record },
        reply_to,
        None,
        vault.store.clock.now_recorded_at(),
    )
}

/// The room whose branch `id` roots, read as the erase doors take `id` away
/// (OF-529): a DAG thread record whose `Parent` is no thread record, or that
/// has none, roots the branch [`thread_root_in_txn`] keyed its appends by. A
/// trunk record, a thread continuation and any other entity root none. The
/// row is read raw, whatever its deletion state, since the erase may have
/// staged its tombstone already; its erasure pin, captured before this runs
/// at both local erase doors, answers first. A parent no row or pin still
/// knows leaves the branch unknown, so nothing is swept for it.
pub(crate) fn erased_thread_room_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    let Some(row) = EntityStoreRead::port_entity_record(store, txn, id)? else {
        return Ok(None);
    };
    if row.entity_type != ENTITY_TYPE_TURN {
        return Ok(None);
    }
    let pin = super::redacted::read(store, txn, id)?;
    let thread = match &pin {
        Some(pin) => pin.thread,
        None => super::topology::record_kind(&row.body)? == Some(RecordKind::Thread),
    };
    if !thread {
        return Ok(None);
    }
    if let Some(parent) = graph::parent(store, txn, id)? {
        match graph::is_thread_record(store, txn, &parent) {
            Ok(false) => {}
            Ok(true) | Err(Error::EntityNotFound) => return Ok(None),
            Err(err) => return Err(err),
        }
    }
    let room = match (super::admission::room_turn_owner(store, txn, id)?, &pin) {
        (Some(owner), Some(pin)) if owner != pin.room => {
            return Err(Error::CorruptedIndex("DAG room pin"));
        }
        (Some(owner), _) => owner,
        (None, Some(pin)) => pin.room,
        (None, None) => return Ok(None),
    };
    Ok(Some(room))
}

/// Every live DAG record of the ordinary room `room`, as the transient turn
/// rows an open offer card's thread fold reads (OF-530). A thread record
/// names the trunk record its thread hangs off and answers its `Parent`, so
/// its root is the one [`thread_root_in_txn`] keys its branch by; a trunk
/// record answers nothing, since the fold places a thread by its trunk and
/// walks no trunk chain. A thread whose walk meets no trunk record, or an
/// ancestor no row or pin still knows, is left out: its branch is unknown.
/// Nothing is stored and no text is copied; the fold reads no author, so a
/// record without one carries none. Every examined row counts toward `count`.
pub(crate) fn offer_turns_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    room: EntityId,
    count: &mut crate::scan_check::ScanCount,
) -> Result<Vec<RoomTurn>> {
    let store = &vault.store;
    let mut records = BTreeMap::new();
    for row in store.port_edges(txn, &room, EdgeDirection::In, Some(EdgeKind::ChildOf), None)? {
        count.row();
        let id = row?.target;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            body,
        } = live_entity_row_in_txn(store, txn, &id)?
        else {
            continue;
        };
        let Some(kind) = super::topology::record_kind(&body)? else {
            continue;
        };
        let at = store
            .port_entity_record(txn, &id)?
            .ok_or(Error::EntityNotFound)?
            .occurred
            .start;
        let actor = crate::conversation::record_author(&body)?
            .map_or_else(String::new, |author| author.to_hex());
        records.insert(id, (kind == RecordKind::Thread, at, actor));
    }
    let mut branches = BTreeMap::new();
    let mut turns = Vec::with_capacity(records.len());
    for (id, (thread, at, actor)) in records {
        let (reply_to, thread_of) = if thread {
            let Some((_, trunk)) = branch_in_txn(store, txn, id, &mut branches)? else {
                continue;
            };
            (graph::parent(store, txn, &id)?, Some(trunk))
        } else {
            (None, None)
        };
        turns.push(RoomTurn {
            turn_id: id.to_hex(),
            room_id: room.to_hex(),
            actor,
            addressed_agents: BTreeSet::new(),
            message_ids: Vec::new(),
            reply_to: reply_to.map(|id| id.to_hex()),
            thread_of: thread_of.map(|id| id.to_hex()),
            at,
            task_ids: Vec::new(),
            converted_project: None,
            quote: None,
        });
    }
    Ok(turns)
}

/// The root and trunk anchor of thread record `record`'s branch: walked up
/// `Parent` through thread records to the first record that is none, at the
/// shared ancestor cap. `None` when the walk meets no trunk record or an
/// ancestor no row or pin still knows. `known` holds each thread record's
/// answer already walked.
fn branch_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    record: EntityId,
    known: &mut BTreeMap<EntityId, Option<(EntityId, EntityId)>>,
) -> Result<Option<(EntityId, EntityId)>> {
    let mut root = record;
    let mut path = vec![record];
    let mut cursor = graph::parent(store, txn, &record)?;
    let found = loop {
        let Some(parent) = cursor else {
            break None;
        };
        if let Some(answer) = known.get(&parent) {
            break *answer;
        }
        match graph::is_thread_record(store, txn, &parent) {
            Ok(true) => {}
            Ok(false) => break Some((root, parent)),
            Err(Error::EntityNotFound) => break None,
            Err(err) => return Err(err),
        }
        if path.len() > MAX_ANCESTOR_DEPTH {
            return Err(Error::IndexOverflow("conversation_dag_walk"));
        }
        root = parent;
        path.push(parent);
        cursor = graph::parent(store, txn, &parent)?;
    };
    for id in path {
        known.insert(id, found);
    }
    Ok(found)
}
