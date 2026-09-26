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
    let prior = store.port_entity_record(txn, id)?;
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

pub(crate) fn pin_membership(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    record: &EntityId,
    kind: EdgeKind,
    conversation: &EntityId,
) -> Result<()> {
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

pub(super) fn record_kind(body: &[u8]) -> Result<Option<&'static str>> {
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

/// Unlike a raw local batch write, a received structural edge may be a
/// replicated side effect of a DAG door. Admit only the defined DAG kinds
/// with live, correctly typed endpoints and the door's structural value.
/// Parent topology is checked here on every replay, including after adoption.
/// Missing cross-window membership defers the edge, not a false peer rejection.
#[cfg(feature = "sync")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceivedEdgeAdmission {
    Admit,
    Deferred,
}

#[cfg(feature = "sync")]
fn received_parent_conversation(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
) -> Result<Option<EntityId>> {
    let owners = super::graph::edge_ids(store, txn, &turn, EdgeKind::ChildOf, false, 2)?;
    let Some(&owner) = owners.first() else {
        return Ok(None);
    };
    if owners.len() != 1 {
        return Err(invalid("received Parent has multiple conversations"));
    }
    match crate::vault::live_entity_row_in_txn(store, txn, &owner)? {
        crate::vault::LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_CONVERSATION,
            ..
        } => Ok(Some(owner)),
        crate::vault::LiveEntityRow::Absent | crate::vault::LiveEntityRow::DeletedShell => Ok(None),
        _ => Err(invalid("received Parent has a non-conversation owner")),
    }
}

#[cfg(feature = "sync")]
pub(crate) fn validate_received_parent(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
    target: EntityId,
) -> Result<ReceivedEdgeAdmission> {
    use super::graph::{self, HEAD};
    use crate::limits::MAX_ANCESTOR_DEPTH;
    use std::collections::HashSet;

    // Parity is an echo, not a new topology mutation. Never replace an
    // already-stored Parent or add a second one for an immutable record.
    if let Some(existing) = graph::parent(store, txn, &source)? {
        return if existing == target {
            Ok(ReceivedEdgeAdmission::Admit)
        } else {
            Err(invalid("received record has a different Parent"))
        };
    }
    let Some(conversation) = received_parent_conversation(store, txn, source)? else {
        return Ok(ReceivedEdgeAdmission::Deferred);
    };
    let target_conversation = received_parent_conversation(store, txn, target)?;
    if target_conversation != Some(conversation) {
        return if target_conversation.is_none() {
            Ok(ReceivedEdgeAdmission::Deferred)
        } else {
            Err(invalid("received Parent crosses conversations"))
        };
    }

    // Walk target's existing ancestors. The proposed source -> target edge
    // forms a cycle exactly when target already descends from source. Also
    // refuse an existing cyclic/cardinality fault instead of extending it.
    let mut seen = HashSet::new();
    let mut cursor = Some(target);
    while let Some(id) = cursor {
        if !seen.insert(id) || id == source {
            return Err(invalid("received Parent contains a cycle"));
        }
        if seen.len() > MAX_ANCESTOR_DEPTH {
            return Err(invalid("received Parent exceeds ancestor depth"));
        }
        if received_parent_conversation(store, txn, id)? != Some(conversation) {
            return Ok(ReceivedEdgeAdmission::Deferred);
        }
        cursor = graph::parent(store, txn, &id)?;
    }
    if let Some(marker) = store.vault_meta.get(txn, &key(MIGRATED, &conversation))? {
        if marker.as_ref() != [1] {
            return Err(Error::CorruptedIndex("conversation DAG migration marker"));
        }
        if let Some(head) = graph::read_id(store, txn, HEAD, &conversation)?
            && graph::chain(store, txn, &conversation, head)?.contains(&source)
        {
            return Err(invalid("received Parent changes the adopted main line"));
        }
    }
    Ok(ReceivedEdgeAdmission::Admit)
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
) -> Result<ReceivedEdgeAdmission> {
    validate_received_edge_shape(store, txn, source, kind, target, value)?;
    if kind == EdgeKind::Parent {
        validate_received_parent(store, txn, source, target)
    } else {
        Ok(ReceivedEdgeAdmission::Admit)
    }
}
