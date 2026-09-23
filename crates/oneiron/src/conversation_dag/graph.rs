//! Strict transactional graph reads and shared guards.

use crate::edge::EdgeKind;
use crate::error::{Error, RecordError, RegistryError, Result};
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use crate::store::Store;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, WriteActor};
use heed::RoTxn;
use std::collections::HashSet;

pub(super) const HEAD: &[u8] = b"conversation_dag:local_head:v1:";
pub(super) const CANONICAL: &[u8] = b"conversation_dag:canonical:v1:";
pub(super) const MIGRATED: &[u8] = b"conversation_dag:migrated:v1:";

pub(super) fn invalid(reason: &'static str) -> Error {
    RecordError::InvalidConversationDag(reason).into()
}

pub(super) fn key(prefix: &[u8], id: &EntityId) -> Vec<u8> {
    [prefix, id.as_bytes()].concat()
}

pub(super) fn read_id(
    store: &Store,
    txn: &RoTxn<'_>,
    prefix: &[u8],
    id: &EntityId,
) -> Result<Option<EntityId>> {
    store
        .vault_meta
        .get(txn, &key(prefix, id))?
        .map(|raw| {
            let bytes: [u8; 16] = raw
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("conversation DAG sidecar"))?;
            EntityId::from_bytes(bytes)
                .map_err(|_| Error::CorruptedIndex("conversation DAG sidecar"))
        })
        .transpose()
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
    require_type(store, txn, record, ENTITY_TYPE_TURN)?;
    let owners = edge_ids(store, txn, record, EdgeKind::ChildOf, false, 2)?;
    if owners.len() != 1 {
        return Err(invalid("record needs exactly one conversation"));
    }
    require_type(store, txn, &owners[0], ENTITY_TYPE_CONVERSATION)?;
    Ok(owners[0])
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
    Ok(parents.first().copied())
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
    let Some(session) = crate::compaction::turn_session_membership_in_txn(store, txn, record)?
    else {
        return Ok(false);
    };
    let body = require_type(store, txn, &session, crate::registry::ENTITY_TYPE_SESSION)?;
    let spawned = edge_ids(store, txn, &session, EdgeKind::SpawnedBy, false, 2)?;
    // A synchronized session's source anchor prevents a missing/late SpawnedBy
    // edge from temporarily reclassifying its worker records as trunk records.
    if let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut body.as_slice()) {
        let anchors: Vec<_> = fields
            .iter()
            .filter(|(k, _)| k.as_str() == Some("dag_spawning_turn"))
            .collect();
        if let Some((_, value)) = anchors.first() {
            let anchor = value
                .as_str()
                .and_then(|value| EntityId::from_hex(value).ok())
                .ok_or(invalid("invalid sub-session anchor"))?;
            if anchors.len() != 1 || spawned != [anchor] {
                return Err(invalid("sub-session anchor has not been reconciled"));
            }
        }
    }
    if spawned.len() > 1 {
        return Err(invalid("session has multiple SpawnedBy edges"));
    }
    if !spawned.is_empty() {
        super::membership::validate_topology(
            store,
            txn,
            conversation_of(store, txn, record)?,
            *record,
        )?;
    }
    Ok(!spawned.is_empty())
}

pub(super) fn is_thread_record(store: &Store, txn: &RoTxn<'_>, record: &EntityId) -> Result<bool> {
    let body = require_type(store, txn, record, ENTITY_TYPE_TURN)?;
    Ok(super::admission::record_kind(&body)? == Some("thread"))
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
