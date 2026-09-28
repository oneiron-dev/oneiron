//! Close the legacy ChildOf-only append door after DAG adoption.
use super::graph::{MIGRATED, invalid};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::ports::{EdgeStoreRead, TombstoneStoreRead};
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

fn body_pin(kind: u8, occurred: crate::TimeRange, learned_at: u64, body: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key("oneiron/conversation-dag/body-pin");
    hash.update(&[kind]);
    hash.update(&occurred.start.to_be_bytes());
    hash.update(&occurred.end.to_be_bytes());
    hash.update(&learned_at.to_be_bytes());
    hash.update(body);
    *hash.finalize().as_bytes()
}

pub(crate) fn guard_record_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    metadata: (u8, crate::TimeRange, u64),
    body: &[u8],
    replicated: bool,
) -> Result<()> {
    let (kind, occurred, learned_at) = metadata;
    if kind == ENTITY_TYPE_TURN
        && let Some((_, recipients)) = addressing(body)?
    {
        // Known wrong-kind recipients are a bad carrier now. Unknown ids
        // remain deferred so an out-of-order peer can deliver PERSON later.
        for recipient in recipients {
            if crate::batch::stored_entity_type(store, txn, &recipient)?
                .is_some_and(|kind| kind != crate::registry::ENTITY_TYPE_PERSON)
            {
                return Err(invalid("recipient is not a PERSON"));
            }
        }
    }
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
                .then(|| body_pin(row.entity_type, row.occurred, row.learned_at, &row.body))
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
    if !replicated || prior.is_none() || pin != body_pin(kind, occurred, learned_at, body) {
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
        header.learned_at,
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

/// Decode the typed record's addressing carrier. Opaque TURNs have no
/// `dag_kind` and keep their existing unstructured-body admission rules.
/// Reference existence is not checked here: a peer may deliver the TURN
/// before its PERSON recipients, reply target, or graph edges.
pub(crate) fn addressing(body: &[u8]) -> Result<Option<(&'static str, Vec<EntityId>)>> {
    let mut bytes = body;
    let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut bytes) else {
        return Ok(None);
    };
    if !fields
        .iter()
        .any(|(key, _)| key.as_str() == Some("dag_kind"))
    {
        return Ok(None);
    }
    if !bytes.is_empty() {
        return Err(invalid("trailing typed record bytes"));
    }
    let mut keys = std::collections::HashSet::new();
    for (key, _) in &fields {
        let name = key
            .as_str()
            .ok_or_else(|| invalid("non-string typed record key"))?;
        if !keys.insert(name) {
            return Err(invalid("duplicate typed record key"));
        }
    }
    let get = |key| {
        fields
            .iter()
            .find(|(name, _)| name.as_str() == Some(key))
            .map(|(_, value)| value)
    };
    let kind = match get("dag_kind").and_then(rmpv::Value::as_str) {
        Some("record") => "record",
        Some("thread") => "thread",
        _ => return Err(invalid("invalid DAG record kind")),
    };
    let mode = match get("addr") {
        None => "broadcast",
        Some(value) => match value.as_str() {
            Some("broadcast") => "broadcast",
            Some("direct") => "direct",
            Some("reply") => "reply",
            _ => return Err(invalid("invalid record address mode")),
        },
    };
    let mut recipients = Vec::new();
    if let Some(value) = get("to") {
        let list = value
            .as_array()
            .ok_or_else(|| invalid("recipients must be an array"))?;
        let mut seen = std::collections::HashSet::new();
        for value in list {
            let hex = value
                .as_str()
                .ok_or_else(|| invalid("recipient must be a PERSON id"))?;
            let id = EntityId::from_hex(hex).map_err(|_| invalid("invalid recipient id"))?;
            if id.to_hex() != hex || !seen.insert(id) {
                return Err(invalid("duplicate or noncanonical recipient id"));
            }
            recipients.push(id);
        }
    }
    if mode == "direct" && recipients.is_empty() {
        return Err(invalid("direct addressing requires recipients"));
    }
    if mode == "broadcast" && !recipients.is_empty() {
        return Err(invalid("broadcast cannot name recipients"));
    }
    if (mode == "reply") != get("reply_to").is_some() || (kind == "thread" && mode != "reply") {
        return Err(invalid("reply addressing requires a reply pointer"));
    }
    Ok(Some((kind, recipients)))
}

/// Structural edge echo: only the stamped recipient set can mandate an
/// AddressedTo edge. The edge carries metadata, never a search weight.
#[cfg(feature = "sync")]
pub(crate) fn addressed_to_echo(
    body: &[u8],
    learned_at: u64,
    target: &EntityId,
    fields: crate::edge::DecodedEdgeValue,
) -> Result<bool> {
    Ok(
        addressing(body)?.is_some_and(|(_, recipients)| recipients.contains(target))
            && fields.layout == crate::edge::EdgeValueLayout::Structural
            && fields.weight == 1.0
            && fields.created_at == learned_at,
    )
}

#[cfg(feature = "sync")]
pub(crate) fn addressed_to_echo_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    source: &EntityId,
    target: &EntityId,
    fields: crate::edge::DecodedEdgeValue,
) -> Result<bool> {
    let Some(raw) = store.entities.get(txn, source.as_bytes())? else {
        return Ok(false);
    };
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("addressing source header"))?;
    if header.entity_type != ENTITY_TYPE_TURN {
        return Ok(false);
    }
    let body = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .ok_or(Error::CorruptedIndex("addressing source body"))?;
    if crate::batch::stored_entity_type(store, txn, target)?
        != Some(crate::registry::ENTITY_TYPE_PERSON)
    {
        return Ok(false);
    }
    addressed_to_echo(body, header.learned_at, target, fields)
}

/// Complete addressing indexes when a received/generic typed record first
/// enters a conversation DAG. The body, not independently supplied edges, is
/// authority. Missing PERSONs defer adoption; no partial HEAD or edge lands.
pub(super) fn reconcile_addressing(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &EntityId,
    body: &[u8],
    learned_at: u64,
) -> Result<()> {
    let Some((_, recipients)) = addressing(body)? else {
        return Ok(());
    };
    let wanted: std::collections::HashSet<_> = recipients.iter().copied().collect();
    let mut present = std::collections::HashSet::new();
    for edge in vault.store.port_edges(
        txn,
        record,
        crate::ports::EdgeDirection::Out,
        Some(EdgeKind::AddressedTo),
        None,
    )? {
        let edge = edge?;
        if !wanted.contains(&edge.target)
            || !present.insert(edge.target)
            || edge.weight != 1.0
            || edge.created_at != learned_at
        {
            return Err(invalid("addressing edge differs from record carrier"));
        }
    }
    for recipient in recipients {
        match super::graph::require_type(
            &vault.store,
            txn,
            &recipient,
            crate::registry::ENTITY_TYPE_PERSON,
        ) {
            Ok(_) => {}
            Err(Error::EntityNotFound)
                if vault.store.port_deletion_state(txn, &recipient)?.deleted =>
            {
                // A terminal addressee is not a pending replica. Keep the
                // historical `to`, but do not resurrect its retired edge.
                continue;
            }
            Err(error) => return Err(error),
        }
        if !present.contains(&recipient) {
            vault
                .batch_in()
                .edge_with_value_fields(
                    record,
                    EdgeKind::AddressedTo,
                    &recipient,
                    super::writes::value(learned_at),
                )
                .apply(txn)?;
        }
    }
    Ok(())
}
pub(super) use super::topology::record_kind;

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
