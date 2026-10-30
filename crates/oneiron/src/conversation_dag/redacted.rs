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
    pin_record_in_txn(&vault.store, txn, id)
}

/// [`pin_record`] on the store alone, for a door that holds no vault.
fn pin_record_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<()> {
    if read(store, txn, id)?.is_some() {
        return Ok(());
    }
    let Some(row) = store.port_entity_record(txn, id)? else {
        return Ok(());
    };
    if row.entity_type != ENTITY_TYPE_TURN {
        return Ok(());
    }
    let rooms = edge_ids(store, txn, id, EdgeKind::ChildOf, false, 2)?;
    let Some(room) = rooms.first().copied() else {
        return Ok(());
    };
    if rooms.len() != 1
        || store
            .port_entity_record(txn, &room)?
            .is_none_or(|owner| owner.entity_type != ENTITY_TYPE_CONVERSATION)
    {
        return Ok(());
    }
    let parents = edge_ids(store, txn, id, EdgeKind::Parent, false, 2)?;
    if parents.len() > 1 {
        return Err(invalid("multiple room parents"));
    }
    let pin = RecordPin {
        room,
        parent: parents.first().copied(),
        session: crate::compaction::turn_session_membership_in_txn(store, txn, id)?,
        thread: super::topology::record_kind(&row.body)?
            == Some(super::topology::RecordKind::Thread),
        author: author(store, txn, &row.body)?,
    };
    PINS.put(store, txn, id, &pin)
}

/// Pins withdrawn record `id`'s topology content-free before its body goes
/// (FIX 931), in the withdrawal's transaction: its body pin becomes the
/// withdrawn pin, its room, parent, session and byline are pinned while its
/// body and edges still read, and its thread's cached projection goes stale.
/// A soft capture: nothing is torn down and no HEAD moves, since the row
/// keeps its header and its edges.
#[cfg(feature = "sync")]
pub(crate) fn capture_withdrawn_record_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    super::admission::withdraw_body_pin(store, txn, id)?;
    pin_record_in_txn(store, txn, id)?;
    super::reply::invalidate_thread_meta(store, txn, *id)
}

/// Pins Shell `id`'s topology content-free from the structural ids its
/// received edges name, typed, never read from body bytes (FIX 11803, L09
/// 01:22): `room`, `parent`, `session` and its `thread` mark. A store that
/// never held a withdrawn reply's body holds only its Shell header, so no
/// withdrawal here pinned it ([`capture_withdrawn_record_in_txn`]). A pin
/// that stands wins, but for its parent and session: one it lacks takes a
/// received value, and a value it holds, its room and its thread mark never
/// change (L09 01:42). Where the full TURN row and its edges are here, local
/// truth pins it ([`pin_record_in_txn`]); otherwise the received ids do,
/// with no author. Only what is local is checked: a room this store holds as
/// anything but a CONVERSATION pins nothing, and a room not yet here still
/// pins; a parent that stands here in another room is left out. Its
/// thread's cached projection goes stale.
#[cfg(feature = "sync")]
pub(crate) fn pin_shell_record_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    room: EntityId,
    parent: Option<EntityId>,
    session: Option<EntityId>,
    thread: bool,
) -> Result<()> {
    if let Some(mut pin) = read(store, txn, id)? {
        let mut filled = false;
        if pin.parent.is_none()
            && let Some(parent) = parent
            && !stands_in_other_room(store, txn, &parent, &pin.room)?
        {
            pin.parent = Some(parent);
            filled = true;
        }
        if pin.session.is_none() && session.is_some() {
            pin.session = session;
            filled = true;
        }
        if !filled {
            return Ok(());
        }
        PINS.put(store, txn, id, &pin)?;
    } else if store
        .port_entity_record(txn, id)?
        .is_some_and(|row| row.entity_type == ENTITY_TYPE_TURN && !row.body.is_empty())
        && !edge_ids(store, txn, id, EdgeKind::ChildOf, false, 2)?.is_empty()
    {
        pin_record_in_txn(store, txn, id)?;
    } else {
        if store
            .port_entity_record(txn, &room)?
            .is_some_and(|owner| owner.entity_type != ENTITY_TYPE_CONVERSATION)
        {
            return Ok(());
        }
        let parent = match parent {
            Some(parent) if stands_in_other_room(store, txn, &parent, &room)? => None,
            parent => parent,
        };
        let pin = RecordPin {
            room,
            parent,
            session,
            thread,
            author: None,
        };
        PINS.put(store, txn, id, &pin)?;
    }
    super::reply::invalidate_thread_meta(store, txn, *id)
}

/// Whether `record` stands here in a room other than `room`: its own ChildOf
/// names another, or, with none, the pin kept for it does. A record not here
/// stands in no room yet.
#[cfg(feature = "sync")]
fn stands_in_other_room(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &EntityId,
    room: &EntityId,
) -> Result<bool> {
    let owners = edge_ids(store, txn, record, EdgeKind::ChildOf, false, 2)?;
    if !owners.is_empty() {
        return Ok(owners != [*room]);
    }
    Ok(read(store, txn, record)?.is_some_and(|pin| pin.room != *room))
}

/// Every erased child `parent` keeps, however many; the walk reading them
/// counts them (rule 5).
pub(crate) fn children(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    parent: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut result = Vec::new();
    for row in CHILDREN.iter_from(store, txn, parent.as_bytes())? {
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
    super::admission::withdraw_body_pin(&vault.store, txn, id)?;
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
