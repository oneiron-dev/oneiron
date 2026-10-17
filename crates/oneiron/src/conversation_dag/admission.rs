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
/// The pin of a deleted record: fixed, so it names no word of the bytes it
/// outlived (ARCH-0038: a hash that outlives its bytes is a confirmation
/// oracle). No body hashes to it, so the id still refuses every re-put.
const WITHDRAWN_PIN: [u8; 32] = [0; 32];
/// Durable room owner of a TURN. The pin survives deleted/missing ChildOf rows.
const ROOM_OWNERS: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::CONVERSATION_DAG_ROOM_OWNER);

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
    // A leader chat is protected before DAG adoption as well. A generic raw
    // TURN + ChildOf pair has no authenticated speaker/project permit.
    if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &conversation)? {
        let body = crate::conversation::ConversationBody::from_bytes(
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        )?;
        if body
            .extra
            .contains_key(crate::workspace_roster::LEADER_CHAT_FIELD)
            && !crate::workspace_roster::leader_chat_record_permitted(
                store,
                txn,
                record,
                conversation,
            )?
        {
            return Err(crate::error::RecordError::ConversationDenied.into());
        }
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
        // remain deferred so an out-of-order peer can deliver the PERSON or
        // AGENT_DEF later (FIX 964).
        for recipient in recipients {
            if crate::batch::stored_entity_type(store, txn, &recipient)?.is_some_and(|kind| {
                !matches!(
                    kind,
                    crate::registry::ENTITY_TYPE_PERSON | crate::registry::ENTITY_TYPE_AGENT_DEF
                )
            }) {
                return Err(invalid("recipient is not a PERSON or AGENT_DEF"));
            }
        }
    }
    if kind == ENTITY_TYPE_TURN
        && let Some(room) = room_turn_owner(store, txn, id)?
    {
        guard_erased_author_body(store, txn, room, body)?;
    }
    // Only a prior TURN is read whole. Any other prior row, a custody record
    // among them, is checked for presence by its type byte, so its body is
    // never copied here.
    let prior_kind = crate::batch::stored_entity_type(store, txn, id)?;
    let prior = if prior_kind == Some(ENTITY_TYPE_TURN) {
        store.port_entity_record(txn, id)?
    } else {
        None
    };
    // A witnessed TURN can predate DAG adoption, so the DAG body pin does not
    // yet protect it. Its PERSON byline is nonetheless an immutable admission
    // fact: a raw local or replicated re-put may re-dirty the row, but cannot
    // assign its earlier words to a new author (or remove that author).
    if kind == ENTITY_TYPE_TURN
        && room_turn_owner(store, txn, id)?.is_some()
        && let Some(previous) = prior.as_ref()
        && !previous.body.is_empty()
        && turn_person(&previous.body)? != turn_person(body)?
    {
        return Err(invalid("room TURN author is immutable"));
    }
    // A TURN's thread binding is a birth fact too (FIX 2951): a raw local or
    // replicated re-put keeps the one it was born with, and only a thread's
    // root names an audience.
    if kind == ENTITY_TYPE_TURN {
        let binding = crate::workspace_roster::thread_binding(body)?;
        if binding
            .as_ref()
            .is_some_and(|binding| binding.audience.is_some() && binding.root != *id)
        {
            return Err(invalid("a thread audience rides its root"));
        }
        if let Some(previous) = prior.as_ref()
            && !previous.body.is_empty()
            && crate::workspace_roster::thread_binding(&previous.body)? != binding
        {
            return Err(invalid("a TURN's thread binding is immutable"));
        }
    }
    let stored_pin = BODY_PINS.get(store, txn, id)?;
    let inferred_pin = if stored_pin.is_none() {
        if let Some(row) = prior.as_ref() {
            adopted_turn_in(store, txn, id, &row.body)?
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
    if !replicated || prior_kind.is_none() || pin != body_pin(kind, occurred, learned_at, body) {
        return Err(invalid("DAG records are append-only"));
    }
    Ok(())
}

/// Whether a stored TURN with no body pin yet is a DAG record all the same:
/// its body carries a typed `dag_kind`, or it belongs to an adopted
/// conversation.
fn adopted_turn_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<bool> {
    let owners = super::graph::edge_ids(store, txn, id, EdgeKind::ChildOf, false, 2)?;
    let mut owned = false;
    for owner in owners {
        owned |= crate::batch::stored_entity_type(store, txn, &owner)?
            == Some(ENTITY_TYPE_CONVERSATION)
            && MIGRATED.get(store, txn, &owner)?.is_some();
    }
    Ok(owned || record_kind(body)?.is_some())
}

/// Whether the record at `id` is an append-only DAG record, which no local
/// put may change: it holds a body pin (a withdrawn one included), or it is
/// a stored TURN [`guard_record_put`] would pin. A witness adding MESSAGE
/// children to such a TURN leaves the TURN row as it is (OF-460).
pub(crate) fn record_is_append_only_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    if BODY_PINS.get(store, txn, id)?.is_some() {
        return Ok(true);
    }
    if crate::batch::stored_entity_type(store, txn, id)? != Some(ENTITY_TYPE_TURN) {
        return Ok(false);
    }
    match store.port_entity_record(txn, id)? {
        Some(row) => adopted_turn_in(store, txn, id, &row.body),
        None => Ok(false),
    }
}

/// The pin of the TURN stored at `id` now, or `None` when `id` holds no TURN.
fn stored_record_pin(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<[u8; 32]>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
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
        // A withdrawn record's shell is not compared: the pin stays withdrawn.
        if prior != pin && prior != WITHDRAWN_PIN {
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
        && crate::ports::EntityStoreRead::port_entity_raw(store, txn, conversation)?
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
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, record)? else {
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
        // A known non-PERSON author is a bad carrier now. An unknown id stays
        // admissible, as recipients do: a peer may deliver the TURN before
        // (or without) its author's PERSON row. The erasure fence is keyed by
        // id and still applies.
        if crate::ports::EntityStoreRead::port_entity_raw(store, txn, &person)?
            .is_some_and(|row| row.first() != Some(&crate::registry::ENTITY_TYPE_PERSON))
        {
            return Err(invalid("room TURN author must be a PERSON"));
        }
        if !crate::conversation::room_person_write_allowed(store, txn, room, person)? {
            return Err(invalid("erased person cannot append to this room"));
        }
    }
    Ok(())
}

pub(crate) fn room_turn_owner(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    record: &EntityId,
) -> Result<Option<EntityId>> {
    if let Some(owner) = ROOM_OWNERS.get(store, txn, record)? {
        return Ok(Some(owner));
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
        if crate::ports::EntityStoreRead::port_entity_raw(store, txn, &target)?
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
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
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
        && crate::ports::EntityStoreRead::port_entity_raw(store, txn, record)?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_TURN))
        && (room_turn_owner(store, txn, record)? == Some(*conversation)
            || crate::ports::EntityStoreRead::port_entity_raw(store, txn, conversation)?
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
        && crate::ports::EntityStoreRead::port_entity_raw(store, txn, record)?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_TURN))
        && crate::ports::EntityStoreRead::port_entity_raw(store, txn, conversation)?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_CONVERSATION))
    {
        guard_erased_person(store, txn, conversation, record)?;
        if room_turn_owner(store, txn, record)?.is_some_and(|owner| owner != *conversation) {
            return Err(invalid("room TURN cannot change owner"));
        }
        ROOM_OWNERS.put(store, txn, record, conversation)?;
    }
    if is_dag_membership(store, txn, kind, conversation)? {
        pin_record(store, txn, record)?;
    }
    Ok(())
}

/// Replace a deleted record's content pin with [`WITHDRAWN_PIN`], before its
/// bytes go. Reached by soft and hard erase, local and replayed.
pub(crate) fn withdraw_body_pin(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    record: &EntityId,
) -> Result<()> {
    if BODY_PINS.get(store, txn, record)?.is_some() {
        BODY_PINS.put(store, txn, record, &WITHDRAWN_PIN)?;
    }
    Ok(())
}

/// The stored body pin of `id`, for checks that a deleted record's pin names
/// none of its words.
#[cfg(test)]
pub(crate) fn stored_body_pin_for_test(
    vault: &crate::Vault,
    id: &EntityId,
) -> Result<Option<[u8; 32]>> {
    let txn = vault.store.env.read_txn()?;
    BODY_PINS.get(&vault.store, &txn, id)
}

/// The delete path's pin: always [`WITHDRAWN_PIN`], never compared.
///
/// A purge may meet a record `user_delete` already reduced to its shell, whose
/// bytes no longer hash to the pin written at append. The withdrawn pin keeps
/// a re-creation after the purge refused without keeping a hash of the words.
pub(crate) fn keep_membership_pin(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    record: &EntityId,
    kind: EdgeKind,
    conversation: &EntityId,
) -> Result<()> {
    if kind == EdgeKind::ChildOf
        && crate::ports::EntityStoreRead::port_entity_raw(store, txn, record)?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_TURN))
        && crate::ports::EntityStoreRead::port_entity_raw(store, txn, conversation)?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_CONVERSATION))
    {
        if let Some(owner) = ROOM_OWNERS.get(store, txn, record)? {
            if owner != *conversation {
                return Err(invalid("room TURN cannot change owner"));
            }
        } else {
            ROOM_OWNERS.put(store, txn, record, conversation)?;
        }
    }
    if !is_dag_membership(store, txn, kind, conversation)? {
        return Ok(());
    }
    if BODY_PINS.get(store, txn, record)?.is_some()
        || stored_record_pin(store, txn, record)?.is_some()
    {
        BODY_PINS.put(store, txn, record, &WITHDRAWN_PIN)?;
    }
    Ok(())
}

/// Decode the typed record's addressing carrier. Opaque TURNs have no
/// `dag_kind` and keep their existing unstructured-body admission rules.
/// Reference existence is not checked here: a peer may deliver the TURN
/// before its PERSON or AGENT_DEF recipients, reply target, or graph edges.
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
                .ok_or_else(|| invalid("recipient must be a PERSON or AGENT_DEF id"))?;
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
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, source)? else {
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
    if !matches!(
        crate::batch::stored_entity_type(store, txn, target)?,
        Some(crate::registry::ENTITY_TYPE_PERSON | crate::registry::ENTITY_TYPE_AGENT_DEF)
    ) {
        return Ok(false);
    }
    addressed_to_echo(body, header.learned_at, target, fields)
}

/// Complete addressing indexes when a received/generic typed record first
/// enters a conversation DAG. The body, not independently supplied edges, is
/// authority. Missing PERSON or AGENT_DEF recipients defer adoption; no
/// partial HEAD or edge lands.
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
        match super::graph::require_recipient(&vault.store, txn, &recipient) {
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
