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

pub(crate) fn pin_record(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(raw) = store.entities().get(txn, id.as_bytes())? else {
        return Ok(());
    };
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("DAG record header"))?;
    if header.entity_type != ENTITY_TYPE_TURN {
        return Ok(());
    }
    let body = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .ok_or(Error::CorruptedIndex("DAG record body"))?;
    let pin = body_pin(
        header.entity_type,
        crate::TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        },
        body,
    );
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

pub(crate) fn pin_membership(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    record: &EntityId,
    kind: EdgeKind,
    conversation: &EntityId,
) -> Result<()> {
    if kind == EdgeKind::ChildOf
        && store
            .vault_meta()
            .get(txn, &key(MIGRATED, conversation))?
            .is_some()
        && store
            .entities()
            .get(txn, conversation.as_bytes())?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_CONVERSATION))
    {
        pin_record(store, txn, record)?;
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
