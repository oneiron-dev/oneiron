//! Close the legacy ChildOf-only append door after DAG adoption.
use super::graph::{MIGRATED, invalid, key};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::EdgeStoreRead;
use crate::ports::EntityStoreRead;
use crate::store::{ManifestDbs, Store};
use crate::{
    EntityId,
    registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN},
};
fn permit_key(record: &EntityId) -> Vec<u8> {
    key(b"conversation_dag:append_in_txn:v1:", record)
}
pub(super) fn permit(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    record: &EntityId,
    conversation: &EntityId,
) -> Result<()> {
    store
        .vault_meta
        .put(txn, &permit_key(record), conversation.as_bytes())?;
    Ok(())
}
pub(super) fn finish(store: &Store, txn: &mut heed::RwTxn<'_>, record: &EntityId) -> Result<()> {
    store.vault_meta.delete(txn, &permit_key(record))?;
    Ok(())
}
/// Reached by both public edge put flavors. Received edge materialization is
/// not a local append and retains the existing replay-validation path.
pub(crate) fn validate_local_membership(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
    kind: EdgeKind,
    conversation: EntityId,
) -> Result<()> {
    if kind != EdgeKind::ChildOf {
        return Ok(());
    }
    let is_kind = |id: &EntityId, kind| -> Result<bool> {
        Ok(store
            .port_entity_record(txn, id)?
            .map(|row| row.encode())
            .is_some_and(|raw| raw.first() == Some(&kind)))
    };
    if !is_kind(&record, ENTITY_TYPE_TURN)? || !is_kind(&conversation, ENTITY_TYPE_CONVERSATION)? {
        return Ok(());
    }
    let marker = store.vault_meta.get(txn, &key(MIGRATED, &conversation))?;
    let Some(marker) = marker else {
        return Ok(());
    };
    if marker.as_ref() != [1] {
        return Err(Error::CorruptedIndex("conversation migration marker"));
    }
    if store
        .port_edge_get(txn, &record, kind, &conversation)?
        .is_some()
    {
        return Ok(());
    }
    if store
        .vault_meta
        .get(txn, &permit_key(&record))?
        .is_some_and(|bytes| bytes.as_ref() == conversation.as_bytes())
    {
        return Ok(());
    }
    Err(invalid(
        "conversation adopted DAG; append through append_dag_record",
    ))
}

fn pin_key(id: &EntityId) -> Vec<u8> {
    key(b"conversation_dag:body_pin:", id)
}

fn body_pin(kind: u8, occurred: crate::TimeRange, body: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key("oneiron/conversation-dag/body-pin");
    hash.update(&[kind]);
    hash.update(&occurred.start.to_be_bytes());
    hash.update(&occurred.end.to_be_bytes());
    hash.update(body);
    *hash.finalize().as_bytes()
}

pub(crate) fn guard_record_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: u8,
    occurred: crate::TimeRange,
    body: &[u8],
    replicated: bool,
) -> Result<()> {
    if kind == ENTITY_TYPE_TURN
        && let Some(room) = room_turn_owner(store, txn, id)?
    {
        guard_erased_author_body(store, txn, room, body)?;
    }
    let prior = store.port_entity_record(txn, id)?;
    // A witnessed TURN can predate DAG adoption, so the DAG body pin does not
    // yet protect it. Its PERSON byline is nonetheless an immutable admission
    // fact: a raw local or replicated re-put may re-dirty the row, but cannot
    // assign its earlier words to a new author (or remove that author).
    if kind == ENTITY_TYPE_TURN
        && room_turn_owner(store, txn, id)?.is_some()
        && let Some(previous) = prior
            .as_ref()
            .filter(|row| row.entity_type == ENTITY_TYPE_TURN)
        && !previous.body.is_empty()
        && turn_person(&previous.body)? != turn_person(body)?
    {
        return Err(invalid("room TURN author is immutable"));
    }
    let stored_pin = store.vault_meta.get(txn, &pin_key(id))?;
    let inferred_pin = if stored_pin.is_none() {
        if let Some(row) = prior
            .as_ref()
            .filter(|row| row.entity_type == ENTITY_TYPE_TURN)
        {
            let owners = super::graph::edge_ids(store, txn, id, EdgeKind::ChildOf, false, 2)?;
            let mut owned = false;
            for owner in owners {
                owned |= store
                    .port_entity_record(txn, &owner)?
                    .is_some_and(|row| row.entity_type == ENTITY_TYPE_CONVERSATION)
                    && store.vault_meta.get(txn, &key(MIGRATED, &owner))?.is_some();
            }
            (owned || record_kind(&row.body)?.is_some())
                .then(|| body_pin(row.entity_type, row.occurred, &row.body))
        } else {
            None
        }
    } else {
        None
    };
    let pin = stored_pin
        .as_deref()
        .or(inferred_pin.as_ref().map(<[u8; 32]>::as_slice));
    let Some(pin) = pin else {
        if kind == ENTITY_TYPE_TURN {
            record_kind(body)?;
        }
        return Ok(());
    };
    if pin.len() != 32 {
        return Err(Error::CorruptedIndex("DAG body pin"));
    }
    if !replicated || prior.is_none() || pin != body_pin(kind, occurred, body) {
        return Err(invalid("DAG records are append-only"));
    }
    Ok(())
}

/// The pin of the TURN stored at `id` now, or `None` when `id` holds no TURN.
fn stored_record_pin(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<[u8; 32]>> {
    let Some(raw) = store.entities().get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("DAG record header"))?;
    if header.entity_type != ENTITY_TYPE_TURN {
        return Ok(None);
    }
    let body = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .ok_or(Error::CorruptedIndex("DAG record body"))?;
    Ok(Some(body_pin(
        header.entity_type,
        crate::TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        },
        body,
    )))
}

pub(crate) fn pin_record(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(pin) = stored_record_pin(store, txn, id)? else {
        return Ok(());
    };
    let key = pin_key(id);
    if let Some(prior) = store.vault_meta().get(txn, &key)? {
        if prior.as_ref() != pin {
            return Err(invalid("DAG records are append-only"));
        }
    } else {
        store.vault_meta().put(txn, &key, &pin)?;
    }
    Ok(())
}

fn is_dag_membership(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    kind: EdgeKind,
    conversation: &EntityId,
) -> Result<bool> {
    Ok(kind == EdgeKind::ChildOf
        && store
            .vault_meta()
            .get(txn, &key(MIGRATED, conversation))?
            .is_some()
        && store
            .entities()
            .get(txn, conversation.as_bytes())?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_CONVERSATION)))
}

/// A local TURN body may carry a PERSON author. Missing authors (for example,
/// imported transcript labels) have no per-person fence to evaluate.
fn turn_person(body: &[u8]) -> Result<Option<EntityId>> {
    let mut bytes = body;
    let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut bytes) else {
        return Ok(None);
    };
    let mut values = fields
        .iter()
        .filter(|(key, _)| key.as_str() == Some("actor"));
    let Some((_, value)) = values.next() else {
        return Ok(None);
    };
    if !bytes.is_empty() || values.next().is_some() {
        return Err(invalid("invalid room TURN author"));
    }
    value
        .as_str()
        .and_then(|text| EntityId::from_hex(text).ok())
        .map(Some)
        .ok_or_else(|| invalid("invalid room TURN author"))
}

fn guard_erased_person(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    room: &EntityId,
    record: &EntityId,
) -> Result<()> {
    let Some(raw) = store.entities().get(txn, record.as_bytes())? else {
        return Ok(());
    };
    if raw.first() != Some(&ENTITY_TYPE_TURN) {
        return Ok(());
    }
    let body = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .ok_or(Error::CorruptedIndex("room TURN header"))?;
    guard_erased_author_body(store, txn, *room, body)
}

fn guard_erased_author_body(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    body: &[u8],
) -> Result<()> {
    if let Some(person) = turn_person(body)? {
        if store
            .entities()
            .get(txn, person.as_bytes())?
            .is_none_or(|row| row.first() != Some(&crate::registry::ENTITY_TYPE_PERSON))
        {
            return Err(invalid("room TURN author must be a PERSON"));
        }
        if !crate::conversation::room_person_write_allowed(store, txn, room, person)? {
            return Err(invalid("erased person cannot append to this room"));
        }
    }
    Ok(())
}

/// Durable room owner of a TURN. The pin survives deleted/missing ChildOf rows.
fn room_owner_key(id: &EntityId) -> Vec<u8> {
    key(b"conversation_dag:room_owner:v1:", id)
}

pub(crate) fn room_turn_owner(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    record: &EntityId,
) -> Result<Option<EntityId>> {
    if let Some(raw) = store.vault_meta().get(txn, &room_owner_key(record))? {
        let bytes: [u8; 16] = raw
            .as_ref()
            .try_into()
            .map_err(|_| Error::CorruptedIndex("room TURN owner pin"))?;
        return EntityId::from_bytes(bytes)
            .map(Some)
            .map_err(|_| Error::CorruptedIndex("room TURN owner pin"));
    }
    let mut owner = None;
    for row in crate::ports::EdgeStoreRead::port_edges(
        store,
        txn,
        record,
        crate::ports::EdgeDirection::Out,
        Some(EdgeKind::ChildOf),
        None,
    )? {
        let target = row?.target;
        if store
            .entities()
            .get(txn, target.as_bytes())?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_CONVERSATION))
            && owner.replace(target).is_some()
        {
            return Err(Error::CorruptedIndex("multiple room TURN owners"));
        }
    }
    Ok(owner)
}

pub(crate) fn guard_room_turn_delete(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(raw) = store.entities().get(txn, id.as_bytes())? else {
        // Refuse reuse even after a prior purge removed the TURN bytes.
        if room_turn_owner(store, txn, id)?.is_some() {
            return Err(invalid("room TURN deletion requires the actor-bound door"));
        }
        return Ok(());
    };
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("room TURN header"))?;
    if header.entity_type == ENTITY_TYPE_TURN
        && (room_turn_owner(store, txn, id)?.is_some()
            || record_kind(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?.is_some())
    {
        return Err(invalid("room TURN deletion requires the actor-bound door"));
    }
    Ok(())
}

pub(crate) fn guard_room_membership_delete(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    record: &EntityId,
    kind: EdgeKind,
    conversation: &EntityId,
) -> Result<()> {
    if kind == EdgeKind::ChildOf
        && store
            .entities()
            .get(txn, record.as_bytes())?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_TURN))
        && (room_turn_owner(store, txn, record)? == Some(*conversation)
            || store
                .entities()
                .get(txn, conversation.as_bytes())?
                .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_CONVERSATION)))
    {
        return Err(invalid(
            "room TURN membership requires the actor-bound door",
        ));
    }
    Ok(())
}

pub(crate) fn pin_membership(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    record: &EntityId,
    kind: EdgeKind,
    conversation: &EntityId,
) -> Result<()> {
    if kind == EdgeKind::ChildOf
        && store
            .entities()
            .get(txn, record.as_bytes())?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_TURN))
        && store
            .entities()
            .get(txn, conversation.as_bytes())?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_CONVERSATION))
    {
        guard_erased_person(store, txn, conversation, record)?;
        if room_turn_owner(store, txn, record)?.is_some_and(|owner| owner != *conversation) {
            return Err(invalid("room TURN cannot change owner"));
        }
        store
            .vault_meta()
            .put(txn, &room_owner_key(record), conversation.as_bytes())?;
    }
    if is_dag_membership(store, txn, kind, conversation)? {
        pin_record(store, txn, record)?;
    }
    Ok(())
}

/// The delete path's pin: written when none is stored, never compared.
///
/// A purge may meet a record `user_delete` already reduced to its shell, whose
/// bytes no longer hash to the pin written at append. The stored pin stays as
/// it is, so a re-creation after the purge is still refused.
pub(crate) fn keep_membership_pin(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    record: &EntityId,
    kind: EdgeKind,
    conversation: &EntityId,
) -> Result<()> {
    if kind == EdgeKind::ChildOf
        && store
            .entities()
            .get(txn, record.as_bytes())?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_TURN))
        && store
            .entities()
            .get(txn, conversation.as_bytes())?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_CONVERSATION))
    {
        let owner_key = room_owner_key(record);
        if let Some(owner) = store.vault_meta().get(txn, &owner_key)? {
            if owner.as_ref() != conversation.as_bytes() {
                return Err(invalid("room TURN cannot change owner"));
            }
        } else {
            store
                .vault_meta()
                .put(txn, &owner_key, conversation.as_bytes())?;
        }
    }
    if !is_dag_membership(store, txn, kind, conversation)? {
        return Ok(());
    }
    let key = pin_key(record);
    if store.vault_meta().get(txn, &key)?.is_none()
        && let Some(pin) = stored_record_pin(store, txn, record)?
    {
        store.vault_meta().put(txn, &key, &pin)?;
    }
    Ok(())
}

pub(crate) fn record_kind(body: &[u8]) -> Result<Option<&'static str>> {
    let mut bytes = body;
    let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut bytes) else {
        return Ok(None);
    };
    let mut kinds = fields
        .iter()
        .filter(|(key, _)| key.as_str() == Some("dag_kind"));
    let Some((_, value)) = kinds.next() else {
        return Ok(None);
    };
    if !bytes.is_empty() || kinds.next().is_some() {
        return Err(invalid("invalid DAG record kind"));
    }
    match value.as_str() {
        Some("record") => Ok(Some("record")),
        Some("thread") => Ok(Some("thread")),
        _ => Err(invalid("invalid DAG record kind")),
    }
}

pub(crate) fn pin_typed_record(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    kind: u8,
    body: &[u8],
) -> Result<()> {
    if kind == ENTITY_TYPE_TURN && record_kind(body)?.is_some() {
        pin_record(store, txn, id)?;
    }
    Ok(())
}

#[cfg(feature = "sync")]
pub(crate) fn validate_received_parent_value(
    source: EntityId,
    target: EntityId,
    value: crate::edge::DecodedEdgeValue,
) -> Result<()> {
    if source == target || value.weight != 1.0 || value.vad.is_some() || value.provenance.is_some()
    {
        return Err(invalid("invalid received DAG edge value"));
    }
    Ok(())
}

#[cfg(feature = "sync")]
pub(crate) fn validate_received_edge_shape(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
    kind: EdgeKind,
    target: EntityId,
    value: crate::edge::DecodedEdgeValue,
) -> Result<()> {
    use crate::registry::{ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
    use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

    let (source_type, target_type) = match kind {
        EdgeKind::Parent | EdgeKind::RepliesTo => (ENTITY_TYPE_TURN, ENTITY_TYPE_TURN),
        EdgeKind::SpawnedBy => (ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN),
        _ => return Err(super::graph::invalid("not a received DAG edge")),
    };
    if source == target || value.weight != 1.0 || value.vad.is_some() || value.provenance.is_some()
    {
        return Err(super::graph::invalid("invalid received DAG edge value"));
    }
    let source_body = match live_entity_row_in_txn(store, txn, &source)? {
        LiveEntityRow::Live { entity_type, body } if entity_type == source_type => body,
        _ => return Err(super::graph::invalid("invalid received DAG edge source")),
    };
    if !matches!(
        live_entity_row_in_txn(store, txn, &target)?,
        LiveEntityRow::Live { entity_type, .. } if entity_type == target_type
    ) {
        return Err(super::graph::invalid("invalid received DAG edge target"));
    }
    if kind == EdgeKind::RepliesTo {
        let mut input = source_body.as_slice();
        let reply_target = rmpv::decode::read_value(&mut input).ok().and_then(|value| {
            let fields = value.as_map()?;
            let mut pointers = fields
                .iter()
                .filter(|(key, _)| key.as_str() == Some("reply_to"));
            let (_, pointer) = pointers.next()?;
            if pointers.next().is_some() {
                return None;
            }
            let mut records = pointer
                .as_map()?
                .iter()
                .filter(|(key, _)| key.as_str() == Some("record"));
            let (_, record) = records.next()?;
            if records.next().is_some() {
                return None;
            }
            EntityId::from_hex(record.as_str()?).ok()
        });
        if !input.is_empty() || reply_target != Some(target) {
            return Err(super::graph::invalid(
                "received reply pointer disagrees with RepliesTo",
            ));
        }
    }
    if kind == EdgeKind::SpawnedBy {
        let mut input = source_body.as_slice();
        let anchor = rmpv::decode::read_value(&mut input).ok().and_then(|value| {
            value.as_map().and_then(|fields| {
                let mut anchors = fields
                    .iter()
                    .filter(|(key, _)| key.as_str() == Some("dag_spawning_turn"));
                let (_, value) = anchors.next()?;
                (anchors.next().is_none())
                    .then(|| value.as_str())
                    .flatten()
                    .and_then(|text| EntityId::from_hex(text).ok())
            })
        });
        if !input.is_empty() || anchor != Some(target) {
            return Err(super::graph::invalid(
                "received session anchor disagrees with SpawnedBy",
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "sync")]
pub(crate) fn validate_received_edge(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
    kind: EdgeKind,
    target: EntityId,
    value: crate::edge::DecodedEdgeValue,
) -> Result<()> {
    validate_received_edge_shape(store, txn, source, kind, target, value)
}
