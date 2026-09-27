//! Content-free, store-local DAG custody across soft and hard erasure.
//! The ordinary delete path removes bodies and incident edges; only typed
//! structural IDs survive here, never a quotation or the erased payload.
use super::graph::{edge_ids, invalid, key};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::store::Store;
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

const PIN: &[u8] = b"conversation_dag:erased_topology:v1:";
const SPAWN: &[u8] = b"conversation_dag:erased_spawn:v1:";
const CHILD: &[u8] = b"conversation_dag:erased_child:v1:";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RecordPin {
    pub room: EntityId,
    pub parent: Option<EntityId>,
    pub session: Option<EntityId>,
    pub thread: bool,
    /// A PERSON byline needed for soft→hard escalation; dropped on hard purge.
    pub author: Option<EntityId>,
}

pub(crate) fn read(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<RecordPin>> {
    store
        .vault_meta
        .get(txn, &key(PIN, id))?
        .map(|bytes| {
            rmp_serde::from_slice(&bytes).map_err(|_| Error::CorruptedIndex("erased DAG topology"))
        })
        .transpose()
}

fn author(store: &Store, txn: &heed::RoTxn<'_>, body: &[u8]) -> Result<Option<EntityId>> {
    let mut input = body;
    let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut input) else {
        return Ok(None);
    };
    if !input.is_empty() {
        return Err(invalid("trailing room author bytes"));
    }
    let mut values = fields.iter().filter(|(k, _)| k.as_str() == Some("actor"));
    let Some((_, value)) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(invalid("duplicate room author"));
    }
    let id = EntityId::from_hex(value.as_str().ok_or(invalid("invalid room author"))?)
        .map_err(|_| invalid("invalid room author"))?;
    let Some(raw) = store.port_entity_record(txn, &id)? else {
        return Ok(None);
    };
    Ok((raw.entity_type == ENTITY_TYPE_PERSON).then_some(id))
}

pub(crate) fn pin_record(vault: &Vault, txn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<()> {
    if read(&vault.store, txn, id)?.is_some() {
        return Ok(());
    }
    let Some(row) = vault.store.port_entity_record(txn, id)? else {
        return Ok(());
    };
    if row.entity_type != ENTITY_TYPE_TURN {
        return Ok(());
    }
    let rooms = edge_ids(&vault.store, txn, id, EdgeKind::ChildOf, false, 2)?;
    let Some(room) = rooms.first().copied() else {
        return Ok(());
    };
    if rooms.len() != 1
        || vault
            .store
            .port_entity_record(txn, &room)?
            .is_none_or(|owner| owner.entity_type != ENTITY_TYPE_CONVERSATION)
    {
        return Ok(());
    }
    let parents = edge_ids(&vault.store, txn, id, EdgeKind::Parent, false, 2)?;
    if parents.len() > 1 {
        return Err(invalid("multiple room parents"));
    }
    let pin = RecordPin {
        room,
        parent: parents.first().copied(),
        session: crate::compaction::turn_session_membership_in_txn(&vault.store, txn, id)?,
        thread: super::admission::record_kind(&row.body)? == Some("thread"),
        author: author(&vault.store, txn, &row.body)?,
    };
    vault.store.vault_meta.put(
        txn,
        &key(PIN, id),
        &rmp_serde::to_vec_named(&pin).map_err(|_| Error::CorruptedIndex("erased DAG topology"))?,
    )?;
    Ok(())
}

pub(crate) fn children(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    parent: &EntityId,
    cap: usize,
) -> Result<Vec<EntityId>> {
    let prefix = key(CHILD, parent);
    let mut result = Vec::new();
    for row in store.vault_meta.prefix_iter(txn, &prefix)? {
        if result.len() >= cap {
            return Err(Error::IndexOverflow("conversation_dag_walk"));
        }
        let (key, value) = row?;
        if key.len() != prefix.len() + 16 || value.as_ref() != [1] {
            return Err(Error::CorruptedIndex("erased DAG child"));
        }
        result.push(EntityId::from_bytes(
            key[prefix.len()..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("erased DAG child"))?,
        )?);
    }
    Ok(result)
}

pub(crate) fn spawned_by(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    session: &EntityId,
) -> Result<Option<EntityId>> {
    let existing = edge_ids(store, txn, session, EdgeKind::SpawnedBy, false, 2)?;
    if let Some(anchor) = existing.first() {
        if existing.len() != 1 {
            return Err(invalid("multiple SpawnedBy edges"));
        }
        return Ok(Some(*anchor));
    }
    store
        .vault_meta
        .get(txn, &key(SPAWN, session))?
        .map(|bytes| {
            EntityId::from_bytes(
                bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("erased session anchor"))?,
            )
        })
        .transpose()
}

/// Runs in the SAME erase txn before `deindex_entity` destroys incident edges.
/// It is reached by the local facade and by replay, including soft→hard.
pub(crate) fn capture_before_erase(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    hard: bool,
) -> Result<()> {
    pin_record(vault, txn, id)?;
    let Some(mut pin) = read(&vault.store, txn, id)? else {
        return Ok(());
    };
    if !hard {
        return Ok(());
    }
    if super::graph::read_id(&vault.store, txn, super::graph::HEAD, &pin.room)? == Some(*id) {
        let old_path = super::graph::chain(&vault.store, txn, &pin.room, *id)?;
        let mut replacement = None;
        for ancestor in old_path.iter().rev().skip(1) {
            if crate::vault::live_entity_row_in_txn(&vault.store, txn, ancestor)?.is_live() {
                replacement = Some(*ancestor);
                break;
            }
        }
        if let Some(replacement) = replacement {
            super::writes::set_head_in_txn(vault, txn, &pin.room, replacement)?;
        } else {
            for ancestor in old_path {
                vault
                    .store
                    .vault_meta
                    .delete(txn, &key(super::graph::CANONICAL, &ancestor))?;
            }
            vault
                .store
                .vault_meta
                .delete(txn, &key(super::graph::HEAD, &pin.room))?;
        }
    }
    // A live descendant loses its outbound Parent when this ancestor is
    // purged. Preserve that descendant's existing, verified topology first.
    let children: Vec<_> = vault
        .store
        .port_edges(txn, id, EdgeDirection::In, Some(EdgeKind::Parent), None)?
        .map(|edge| edge.map(|e| e.target))
        .collect::<Result<_>>()?;
    for child in children {
        pin_record(vault, txn, &child)?;
        if read(&vault.store, txn, &child)?
            .is_some_and(|child_pin| child_pin.parent == Some(*id) && child_pin.room == pin.room)
        {
            let mut child_key = key(CHILD, id);
            child_key.extend_from_slice(child.as_bytes());
            vault.store.vault_meta.put(txn, &child_key, &[1])?;
        }
    }
    let sessions: Vec<_> = vault
        .store
        .port_edges(txn, id, EdgeDirection::In, Some(EdgeKind::SpawnedBy), None)?
        .map(|edge| edge.map(|e| e.target))
        .collect::<Result<_>>()?;
    for session in sessions {
        vault
            .store
            .vault_meta
            .put(txn, &key(SPAWN, &session), id.as_bytes())?;
    }
    pin.author = None;
    vault.store.vault_meta.put(
        txn,
        &key(PIN, id),
        &rmp_serde::to_vec_named(&pin).map_err(|_| Error::CorruptedIndex("erased DAG topology"))?,
    )?;
    Ok(())
}
