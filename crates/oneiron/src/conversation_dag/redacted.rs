//! Content-free, store-local DAG custody across soft and hard erasure.
//! The ordinary delete path removes bodies and incident edges; only typed
//! structural IDs survive here, never a quotation or the erased payload.
use super::graph::{edge_ids, invalid};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

/// Content-free topology pin of an erased DAG record, by record id.
const PINS: SideTable<EntityId, RecordPin, Named> =
    SideTable::new(&side_table::CONVERSATION_DAG_ERASED_TOPOLOGY);
/// SpawnedBy anchor of a session whose anchoring record was purged, by session.
const SPAWNS: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::CONVERSATION_DAG_ERASED_SPAWN);
/// `[1]` reverse Parent witness of a purged record, keyed by `(parent, child)`.
const CHILDREN: SideTable<(EntityId, EntityId), [u8; 1], Raw> =
    SideTable::new(&side_table::CONVERSATION_DAG_ERASED_CHILD);

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
    PINS.get(store, txn, id)
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
        thread: super::topology::record_kind(&row.body)?
            == Some(super::topology::RecordKind::Thread),
        author: author(&vault.store, txn, &row.body)?,
    };
    PINS.put(&vault.store, txn, id, &pin)
}

pub(crate) fn children(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    parent: &EntityId,
    cap: usize,
) -> Result<Vec<EntityId>> {
    let mut result = Vec::new();
    for row in CHILDREN.iter_from(store, txn, parent.as_bytes())? {
        if result.len() >= cap {
            return Err(Error::IndexOverflow("conversation_dag_walk"));
        }
        let ((_, child), value) = row?;
        if value != [1] {
            return Err(Error::CorruptedIndex("erased DAG child"));
        }
        result.push(child);
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
    SPAWNS.get(store, txn, session)
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
                super::graph::CANONICAL.delete(&vault.store, txn, &ancestor)?;
            }
            super::graph::HEAD.delete(&vault.store, txn, &pin.room)?;
        }
    }
    // This record also loses its own outbound Parent. Keep the reverse
    // witness so fork expansion can reach it from its ancestor after purge.
    // The pin was captured while the edge still existed (or at soft erase).
    if let Some(parent) = pin.parent {
        super::graph::require_member(&vault.store, txn, &pin.room, &parent)?;
        CHILDREN.put(&vault.store, txn, &(parent, *id), &[1])?;
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
            CHILDREN.put(&vault.store, txn, &(*id, child), &[1])?;
        }
    }
    let sessions: Vec<_> = vault
        .store
        .port_edges(txn, id, EdgeDirection::In, Some(EdgeKind::SpawnedBy), None)?
        .map(|edge| edge.map(|e| e.target))
        .collect::<Result<_>>()?;
    for session in sessions {
        SPAWNS.put(&vault.store, txn, &session, id)?;
    }
    pin.author = None;
    PINS.put(&vault.store, txn, id, &pin)
}
