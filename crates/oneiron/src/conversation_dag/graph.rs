//! Strict transactional graph reads and shared guards.

use crate::edge::EdgeKind;
use crate::error::{Error, RecordError, RegistryError, Result};
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, WriteActor};
use heed::RoTxn;
use std::collections::HashSet;

/// Per-conversation pointer to the current local-head DAG record id.
pub(super) const HEAD: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::CONVERSATION_DAG_LOCAL_HEAD);
/// Forward canonical-chain link: one DAG record to its canonical successor.
pub(super) const CANONICAL: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::CONVERSATION_DAG_CANONICAL);
/// Single-byte `[1]` marker that a conversation has adopted the DAG record model.
pub(super) const MIGRATED: SideTable<EntityId, [u8; 1], Raw> =
    SideTable::new(&side_table::CONVERSATION_DAG_MIGRATED);

pub(super) fn invalid(reason: &'static str) -> Error {
    RecordError::InvalidConversationDag(reason).into()
}

pub(super) fn read_id(
    store: &Store,
    txn: &RoTxn<'_>,
    table: SideTable<EntityId, EntityId, Raw>,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    table.get(store, txn, id)
}

pub(crate) fn require_type(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    expected: u8,
) -> Result<Vec<u8>> {
    match live_entity_row_in_txn(store, txn, id)? {
        LiveEntityRow::Live { entity_type, body } if entity_type == expected => Ok(body),
        LiveEntityRow::Live { .. } => Err(invalid("unexpected entity type")),
        _ => Err(Error::EntityNotFound),
    }
}

pub(crate) fn actor_in_txn(store: &Store, txn: &RoTxn<'_>, actor: WriteActor) -> Result<()> {
    match live_entity_row_in_txn(store, txn, &actor.entity_ref())? {
        LiveEntityRow::Live { entity_type, .. } => {
            crate::provenance::validate_actor_class(entity_type, actor.actor_class())
        }
        _ => Err(Error::EntityNotFound),
    }
}

/// Counts examined rows, not only live results. A forged index cannot bypass
/// the work bound by filling a neighborhood with tombstones.
pub(crate) fn edge_ids(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    kind: EdgeKind,
    incoming: bool,
    cap: usize,
) -> Result<Vec<EntityId>> {
    let direction = if incoming {
        EdgeDirection::In
    } else {
        EdgeDirection::Out
    };
    let mut ids = Vec::new();
    for (n, entry) in store
        .port_edges(txn, id, direction, Some(kind), None)?
        .enumerate()
    {
        if n >= cap {
            return Err(Error::IndexOverflow("conversation_dag_walk"));
        }
        let edge = entry?;
        if edge.kind != kind {
            return Err(Error::CorruptedIndex("conversation DAG edge"));
        }
        ids.push(edge.target);
    }
    Ok(ids)
}

pub(crate) fn conversation_of(
    store: &Store,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<EntityId> {
    let row = live_entity_row_in_txn(store, txn, record)?;
    let pin = super::redacted::read(store, txn, record)?;
    let room = match row {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            ..
        } => {
            let owners = edge_ids(store, txn, record, EdgeKind::ChildOf, false, 2)?;
            if owners.len() != 1 {
                return Err(invalid("record needs exactly one conversation"));
            }
            if pin.as_ref().is_some_and(|pin| pin.room != owners[0]) {
                return Err(Error::CorruptedIndex("DAG room pin"));
            }
            owners[0]
        }
        LiveEntityRow::DeletedShell | LiveEntityRow::Absent => {
            pin.ok_or(Error::EntityNotFound)?.room
        }
        _ => return Err(invalid("unexpected entity type")),
    };
    require_type(store, txn, &room, ENTITY_TYPE_CONVERSATION)?;
    Ok(room)
}

pub(super) fn require_member(
    store: &Store,
    txn: &RoTxn<'_>,
    conversation: &EntityId,
    record: &EntityId,
) -> Result<()> {
    if conversation_of(store, txn, record)? != *conversation {
        return Err(RecordError::DagParentOutsideConversation.into());
    }
    Ok(())
}

pub(super) fn parent(
    store: &Store,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<Option<EntityId>> {
    let parents = edge_ids(store, txn, record, EdgeKind::Parent, false, 2)?;
    if parents.len() > 1 {
        return Err(invalid("record has multiple Parent edges"));
    }
    let pin = super::redacted::read(store, txn, record)?;
    if let Some(edge) = parents.first() {
        if pin.as_ref().is_some_and(|pin| pin.parent != Some(*edge)) {
            return Err(Error::CorruptedIndex("DAG Parent pin"));
        }
        return Ok(Some(*edge));
    }
    Ok(pin.and_then(|pin| pin.parent))
}

/// Walks backwards from a leaf, proving live membership, cardinality and
/// acyclicity at every step. No partial result is ever returned.
pub(super) fn chain(
    store: &Store,
    txn: &RoTxn<'_>,
    conversation: &EntityId,
    leaf: EntityId,
) -> Result<Vec<EntityId>> {
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    let mut cursor = Some(leaf);
    while let Some(id) = cursor {
        if !seen.insert(id) {
            return Err(RegistryError::CycleDetected.into());
        }
        if records.len() >= MAX_ANCESTOR_DEPTH {
            return Err(Error::IndexOverflow("conversation_dag_walk"));
        }
        require_member(store, txn, conversation, &id)?;
        records.push(id);
        cursor = parent(store, txn, &id)?;
    }
    records.reverse();
    Ok(records)
}

pub(crate) fn is_sub_session_record(
    store: &Store,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<bool> {
    let session = crate::compaction::turn_session_membership_in_txn(store, txn, record)?
        .or(super::redacted::read(store, txn, record)?.and_then(|pin| pin.session));
    let Some(session) = session else {
        return Ok(false);
    };
    let conversation = conversation_of(store, txn, record)?;
    match super::topology::classify_session(store, txn, session, conversation)? {
        super::topology::Fact::Known(super::topology::SessionPlacement::Ordinary { .. }) => {
            Ok(false)
        }
        super::topology::Fact::Known(
            placement @ super::topology::SessionPlacement::Spawned { .. },
        ) => {
            super::membership::validate_topology(store, txn, conversation, *record, placement)?;
            Ok(true)
        }
        super::topology::Fact::Wait(_) => {
            Err(invalid("sub-session anchor has not been reconciled"))
        }
        super::topology::Fact::Reject(reason) => Err(reason.into_error()),
    }
}

pub(super) fn is_thread_record(store: &Store, txn: &RoTxn<'_>, record: &EntityId) -> Result<bool> {
    match live_entity_row_in_txn(store, txn, record)? {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            body,
        } => Ok(super::topology::record_kind(&body)? == Some(super::topology::RecordKind::Thread)),
        LiveEntityRow::DeletedShell | LiveEntityRow::Absent => {
            Ok(super::redacted::read(store, txn, record)?
                .ok_or(Error::EntityNotFound)?
                .thread)
        }
        _ => Err(invalid("unexpected entity type")),
    }
}

pub(super) fn canonical_chain(
    store: &Store,
    txn: &RoTxn<'_>,
    conversation: &EntityId,
) -> Result<Vec<EntityId>> {
    let head = read_id(store, txn, HEAD, conversation)?;
    let path = head
        .map(|head| chain(store, txn, conversation, head))
        .transpose()?
        .unwrap_or_default();
    for (n, id) in path.iter().enumerate() {
        if is_thread_record(store, txn, id)? {
            return Err(invalid("thread record on canonical line"));
        }
        if is_sub_session_record(store, txn, id)? {
            return Err(invalid("sub-session record on canonical line"));
        }
        if read_id(store, txn, CANONICAL, id)? != path.get(n + 1).copied() {
            return Err(Error::CorruptedIndex("conversation canonical mark"));
        }
    }
    Ok(path)
}
