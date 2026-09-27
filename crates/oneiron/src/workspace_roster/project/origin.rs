//! Durable origin proof and local secondary indexes for converted projects.
use super::*;
use crate::edge::EdgeKind;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::store::Store;
use rmpv::Value;

pub(super) const BY_THREAD: &[u8] = b"project.origin_thread.v1/";
pub(super) const BY_MESSAGE: &[u8] = b"project.origin_message.v1/";
pub(super) const BY_PROJECT: &[u8] = b"project.origin_by_project.v1/";

pub(super) fn thread_key(room: EntityId, thread: EntityId) -> Vec<u8> {
    [BY_THREAD, room.as_bytes(), thread.as_bytes()].concat()
}
pub(super) fn message_prefix(message: EntityId) -> Vec<u8> {
    [BY_MESSAGE, message.as_bytes()].concat()
}
fn project_key(project: EntityId) -> Vec<u8> {
    [BY_PROJECT, project.as_bytes()].concat()
}
fn message_key(message: EntityId, project: EntityId) -> Vec<u8> {
    [message_prefix(message).as_slice(), project.as_bytes()].concat()
}
fn reject() -> Error {
    crate::error::RecordError::InvalidProjectBody("invalid project origin").into()
}
fn pending() -> Error {
    crate::error::RecordError::ProjectDependencyPending.into()
}
fn present(store: &Store, txn: &heed::RoTxn<'_>, id: EntityId, kind: u8) -> Result<Vec<u8>> {
    let raw = store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or_else(pending)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(reject)?;
    if header.entity_type != kind || raw.len() == ENTITY_METADATA_HEADER_LEN {
        return Err(reject());
    }
    Ok(raw[ENTITY_METADATA_HEADER_LEN..].to_vec())
}
fn sole_edge(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: EdgeKind,
    target: EntityId,
) -> Result<()> {
    let ids =
        crate::conversation_dag::edge_ids(store, txn, &id, kind, false, 2).map_err(|_| reject())?;
    match ids.as_slice() {
        [] => Err(pending()),
        [one] if *one == target => Ok(()),
        _ => Err(reject()),
    }
}
fn marker_parent(body: &[u8]) -> Result<Option<EntityId>> {
    let mut input = body;
    let decoded = rmpv::decode::read_value(&mut input).map_err(|_| reject())?;
    if !input.is_empty() {
        return Err(reject());
    }
    let Value::Map(fields) = decoded else {
        return Err(reject());
    };
    let metadata = fields.iter().find(|(k, _)| k.as_str() == Some("metadata"));
    let Some((_, Value::Map(metadata))) = metadata else {
        return Ok(None);
    };
    metadata
        .iter()
        .find(|(k, _)| k.as_str() == Some("room_thread_of"))
        .map(|(_, value)| {
            EntityId::from_hex(value.as_str().ok_or_else(reject)?).map_err(|_| reject())
        })
        .transpose()
}
/// Common put/replay proof. Only replicated entity bodies and edges count;
/// room-turn sidecars exist only on the witnessing device.
pub(super) fn validate_binding(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &ProjectRecord,
) -> Result<()> {
    let (Some(message), Some(room), Some(thread), Some(at)) = (
        &body.born_from,
        &body.origin_room,
        &body.origin_thread,
        body.origin_at,
    ) else {
        return Ok(());
    };
    let message = EntityId::from_hex(message).map_err(|_| reject())?;
    let room = EntityId::from_hex(room).map_err(|_| reject())?;
    let thread = EntityId::from_hex(thread).map_err(|_| reject())?;
    let source: ProjectRoom =
        record(store, txn, room, ENTITY_TYPE_CONVERSATION)?.ok_or_else(pending)?;
    if !body.parents.contains(&source.project_id) {
        return Err(reject());
    }
    let source_project = EntityId::from_hex(&source.project_id).map_err(|_| reject())?;
    let kind = project_type(store).ok_or_else(pending)?;
    let owner: ProjectRecord = record(store, txn, source_project, kind)?.ok_or_else(pending)?;
    if owner.home_room != room.to_hex()
        || owner.roster != source.member_ids
        || owner.claims_scope_ref != source.claims_scope_ref
        || source.kind != "channel"
    {
        return Err(reject());
    }
    // The source message must be INSIDE the selected thread, not on its trunk parent.
    present(store, txn, message, ENTITY_TYPE_MESSAGE)?;
    let turn = crate::conversation_dag::edge_ids(store, txn, &message, EdgeKind::PartOf, false, 2)
        .map_err(|_| reject())?;
    match turn.as_slice() {
        [] => return Err(pending()),
        [only] if *only == thread => {}
        _ => return Err(reject()),
    }
    sole_edge(store, txn, message, EdgeKind::BelongsTo, room)?;
    let raw_thread = store
        .entities
        .get(txn, thread.as_bytes())?
        .ok_or_else(pending)?;
    let header = EntityMetadataHeader::parse(&raw_thread).ok_or_else(reject)?;
    if header.entity_type != ENTITY_TYPE_TURN
        || raw_thread.len() == ENTITY_METADATA_HEADER_LEN
        || header.occurred_start != at
    {
        return Err(reject());
    }
    sole_edge(store, txn, thread, EdgeKind::ChildOf, room)?;
    // A witnessed thread has at least one message carrying its parent turn.
    let mut marker = None;
    for child in
        crate::conversation_dag::edge_ids(store, txn, &thread, EdgeKind::PartOf, true, 65536)?
    {
        let bytes = present(store, txn, child, ENTITY_TYPE_MESSAGE)?;
        if let Some(parent) = marker_parent(&bytes)?
            && marker.replace(parent).is_some_and(|prior| prior != parent)
        {
            return Err(reject());
        }
    }
    let parent = marker.ok_or_else(pending)?;
    present(store, txn, parent, ENTITY_TYPE_TURN)?;
    sole_edge(store, txn, parent, EdgeKind::ChildOf, room)?;
    Ok(())
}

/// The same final-state projector owns these indexes for direct and replay puts.
pub(super) fn index_origin(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    body: &ProjectRecord,
) -> Result<()> {
    let reverse = project_key(id);
    let prior = store
        .vault_meta
        .get(txn, &reverse)?
        .map(|bytes| bytes.to_vec());
    let Some(message) = &body.born_from else {
        if prior.is_some() {
            return Err(reject());
        } // birth cannot be erased by a later update
        return Ok(());
    };
    let room = EntityId::from_hex(body.origin_room.as_deref().ok_or_else(reject)?)?;
    let thread = EntityId::from_hex(body.origin_thread.as_deref().ok_or_else(reject)?)?;
    let message = EntityId::from_hex(message)?;
    let key = thread_key(room, thread);
    let expected = [
        room.as_bytes().as_slice(),
        thread.as_bytes(),
        message.as_bytes(),
    ]
    .concat();
    if prior.as_ref().is_some_and(|old| old != &expected) {
        return Err(reject());
    }
    if let Some(owner) = store.vault_meta.get(txn, &key)?
        && owner.as_ref() != id.as_bytes()
    {
        return Err(reject());
    }
    store.vault_meta.put(txn, &key, id.as_bytes())?;
    store
        .vault_meta
        .put(txn, &message_key(message, id), id.as_bytes())?;
    store.vault_meta.put(txn, &reverse, &expected)?;
    Ok(())
}
pub(super) fn deindex_origin(store: &Store, txn: &mut heed::RwTxn<'_>, id: EntityId) -> Result<()> {
    let reverse = project_key(id);
    let Some(bytes) = store.vault_meta.get(txn, &reverse)? else {
        return Ok(());
    };
    let refs: [u8; 48] = bytes
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex("project origin reverse"))?;
    let room = EntityId::from_bytes(refs[..16].try_into().map_err(|_| reject())?)?;
    let thread = EntityId::from_bytes(refs[16..32].try_into().map_err(|_| reject())?)?;
    let message = EntityId::from_bytes(refs[32..].try_into().map_err(|_| reject())?)?;
    let key = thread_key(room, thread);
    if store.vault_meta.get(txn, &key)?.as_deref() != Some(id.as_bytes()) {
        return Err(Error::CorruptedIndex("project origin index"));
    }
    store.vault_meta.delete(txn, &key)?;
    store.vault_meta.delete(txn, &message_key(message, id))?;
    store.vault_meta.delete(txn, &reverse)?;
    Ok(())
}
