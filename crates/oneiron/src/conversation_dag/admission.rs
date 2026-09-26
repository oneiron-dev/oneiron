//! Close the legacy ChildOf-only append door after DAG adoption.
use super::graph::{MIGRATED, invalid};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::EdgeStoreRead;
use crate::ports::EntityStoreRead;
use crate::side_table::{self, Raw, SideTable};
use crate::store::{ManifestDbs, Store};
use crate::{
    EntityId,
    registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN},
};

/// Transient in-txn permit binding a legacy ChildOf-append record id to the
/// conversation it may write.
const APPEND_PERMITS: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::CONVERSATION_DAG_APPEND_PERMIT);
/// Content pin of one immutable DAG record body, by record id.
const BODY_PINS: SideTable<EntityId, [u8; 32], Raw> =
    SideTable::new(&side_table::CONVERSATION_DAG_BODY_PIN);

pub(super) fn permit(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    record: &EntityId,
    conversation: &EntityId,
) -> Result<()> {
    APPEND_PERMITS.put(store, txn, record, conversation)
}
pub(super) fn finish(store: &Store, txn: &mut heed::RwTxn<'_>, record: &EntityId) -> Result<()> {
    APPEND_PERMITS.delete(store, txn, record)?;
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
    let marker = MIGRATED.get(store, txn, &conversation)?;
    let Some(marker) = marker else {
        return Ok(());
    };
    if marker != [1] {
        return Err(Error::CorruptedIndex("conversation migration marker"));
    }
    if store
        .port_edge_get(txn, &record, kind, &conversation)?
        .is_some()
    {
        return Ok(());
    }
    if APPEND_PERMITS
        .get(store, txn, &record)?
        .is_some_and(|bound| bound == conversation)
    {
        return Ok(());
    }
    Err(invalid(
        "conversation adopted DAG; append through append_dag_record",
    ))
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
    let stored_pin = BODY_PINS.get(store, txn, id)?;
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
                    && MIGRATED.get(store, txn, &owner)?.is_some();
            }
            (owned || record_kind(&row.body)?.is_some())
                .then(|| body_pin(row.entity_type, row.occurred, &row.body))
        } else {
            None
        }
    } else {
        None
    };
    let pin = stored_pin.or(inferred_pin);
    let Some(pin) = pin else {
        if kind == ENTITY_TYPE_TURN {
            record_kind(body)?;
        }
        return Ok(());
    };
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
    if let Some(prior) = BODY_PINS.get(store, txn, id)? {
        if prior != pin {
            return Err(invalid("DAG records are append-only"));
        }
    } else {
        BODY_PINS.put(store, txn, id, &pin)?;
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
        && MIGRATED.get(store, txn, conversation)?.is_some()
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
    if BODY_PINS.get(store, txn, record)?.is_none()
        && let Some(pin) = stored_record_pin(store, txn, record)?
    {
        BODY_PINS.put(store, txn, record, &pin)?;
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
