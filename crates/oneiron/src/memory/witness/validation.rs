//! Idempotency validators: turn/message existence, parent/actor binding, order collision axes.

use super::super::*;
use super::codec::decode_witness_turn_person;
use super::decode_witness_turn_speaker;
use crate::ports::EdgeStoreRead;
use crate::ports::{EntityRecord, EntityStoreRead};

use std::collections::{BTreeSet, HashSet};

use rmpv::Value;

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError};
use crate::gate::{MAX_WITNESS_MESSAGE_ORDER, validate_canonical_witness_message_body};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::store::ManifestDbs;

/// Tolerated clock skew for a witnessed turn's occurrence time (seconds), as
/// for a reaction's.
const WITNESS_OCCURRENCE_SKEW_SECS: u64 = 300;

/// A witnessed row is learned as it occurs, so a time past the store clock's
/// skew would carry the consolidation watermark past every later turn. It is
/// refused at the witness and structural doors (F30); an import keeps its own
/// learned time.
pub(in crate::memory) fn validate_witness_occurrence(
    now: u64,
    occurred_at: u64,
) -> MemoryResult<()> {
    if occurred_at > now.saturating_add(WITNESS_OCCURRENCE_SKEW_SECS) {
        return Err(MemoryError::bad_request("turn time is in the future"));
    }
    Ok(())
}

/// Returns the one target an existing structural edge kind names. More than
/// one target is already a re-parented row and therefore fails closed.
pub(crate) fn sole_edge_target(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    source: &EntityId,
    kind: EdgeKind,
    label: &'static str,
) -> MemoryResult<Option<EntityId>> {
    let mut target = None;
    for row in dbs.port_edges(
        txn,
        source,
        crate::ports::EdgeDirection::Out,
        Some(kind),
        None,
    )? {
        let candidate = row?.target;
        if target.replace(candidate).is_some() {
            return Err(MemoryError::bad_request(format!(
                "an existing witnessed {label} has more than one {kind:?} parent"
            )));
        }
    }
    Ok(target)
}

/// Reads a deterministic TURN and, when it exists, proves that retrying it
/// cannot move it under another conversation or speaker. `Some` is the
/// verified stored row.
pub(super) fn validate_existing_witness_turn(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    turn_id: &EntityId,
    conversation_id: &EntityId,
    incoming_speaker: Option<&str>,
    _incoming_person: Option<EntityId>,
) -> MemoryResult<Option<EntityRecord>> {
    let Some(raw) = dbs.port_entity_record(txn, turn_id)? else {
        return Ok(None);
    };

    if raw.entity_type != ENTITY_TYPE_TURN {
        return Err(MemoryError::bad_request(
            "the witnessed turn ref resolves to a non-TURN entity",
        ));
    }
    // The first writer's PERSON byline is immutable. A later witness call may
    // append messages under a different actor (including a SYSTEM interleave)
    // without claiming to become the author of the existing TURN. The re-put
    // below preserves these bytes exactly; malformed stored bylines still fail.
    decode_witness_turn_person(&raw.body)?;
    let stored_speaker = decode_witness_turn_speaker(&raw.body)?;
    if incoming_speaker.is_some_and(|incoming| incoming != stored_speaker) {
        return Err(MemoryError::bad_request(
            "the witnessed turn already belongs to another speaker",
        ));
    }
    if sole_edge_target(dbs, txn, turn_id, EdgeKind::ChildOf, "turn")? != Some(*conversation_id) {
        return Err(MemoryError::bad_request(
            "the witnessed turn already belongs to another conversation",
        ));
    }
    Ok(Some(raw))
}

/// A stored TURN's reply topology is a birth fact (OF-460): the room guard
/// fixes one only for a TURN its write mints, and each message's quote is
/// checked against that message's own kept one there (FIX 2028), so a stored
/// TURN takes none here.
pub(super) fn validate_existing_witness_quote(
    incoming: Option<&crate::conversation_dag::QuotedReply>,
) -> MemoryResult<()> {
    if incoming.is_some() {
        return Err(MemoryError::bad_request(
            "the witnessed turn's reply is fixed when it is minted",
        ));
    }
    Ok(())
}

/// Checks whether a deterministic MESSAGE already exists. Its canonical body
/// and all three structural bindings are immutable together: exact retries are
/// no-ops, while changed text/kind/order/visibility or a new parent/actor is a
/// refusal rather than an overwrite or a second edge.
///
/// `expected_author` is the `AuthoredBy` target the landing writes: the bound
/// actor for an attributed row, none for a system row or an imported one.
pub(super) fn validate_existing_witness_message(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    message_id: &EntityId,
    body: &[u8],
    turn_id: &EntityId,
    conversation_id: &EntityId,
    expected_author: Option<EntityId>,
) -> MemoryResult<bool> {
    let Some(raw) = dbs.port_entity_record(txn, message_id)? else {
        return Ok(false);
    };

    if raw.entity_type != ENTITY_TYPE_MESSAGE {
        return Err(MemoryError::bad_request(
            "the witnessed message id resolves to a non-MESSAGE entity",
        ));
    }
    if raw.body != body {
        return Err(Error::Record(RecordError::InvalidWitnessMessageBody(
            "an existing MESSAGE id is bound to its original canonical body",
        ))
        .into());
    }
    if sole_edge_target(dbs, txn, message_id, EdgeKind::PartOf, "message")? != Some(*turn_id) {
        return Err(MemoryError::bad_request(
            "the witnessed message already belongs to another turn",
        ));
    }
    if sole_edge_target(dbs, txn, message_id, EdgeKind::BelongsTo, "message")?
        != Some(*conversation_id)
    {
        return Err(MemoryError::bad_request(
            "the witnessed message already belongs to another conversation",
        ));
    }
    let authored_by = sole_edge_target(dbs, txn, message_id, EdgeKind::AuthoredBy, "message")?;
    if authored_by != expected_author {
        return Err(MemoryError::bad_request(
            "the witnessed message already belongs to another actor",
        ));
    }
    Ok(true)
}

/// Checks the ORDER axis against all already-persisted MESSAGE children of one
/// existing TURN. An append is a new call, but its positions still share the
/// turn's one reader-visible domain: a new message may not claim a slot an
/// earlier call already occupied. Exact retries are exempt by message id after
/// their canonical body and parent/actor topology have been verified above.
pub(super) fn validate_existing_witness_message_orders(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    turn_id: &EntityId,
    messages: &[WitnessMessage],
    existing_message_ids: &HashSet<EntityId>,
) -> MemoryResult<()> {
    let mut incoming = BTreeSet::new();
    for message in messages {
        if message.order > MAX_WITNESS_MESSAGE_ORDER {
            return Err(MemoryError::bad_request(format!(
                "witness message order {} exceeds the {MAX_WITNESS_MESSAGE_ORDER} ceiling",
                message.order,
            )));
        }
        incoming.insert(message.order);
    }
    match taken_witness_message_order(dbs, txn, turn_id, &incoming, existing_message_ids)? {
        Some(order) => Err(MemoryError::bad_request_with(
            format!("witness message order {order} collides with an existing message in this turn"),
            &["Give each message in a turn its own position."],
        )),
        None => Ok(()),
    }
}

/// The first of `incoming` a persisted MESSAGE child of `turn_id` already
/// holds, leaving out the `exempt` children (a caller's exact retries).
///
/// Only an incoming order is refused. Two stored children that share an order
/// already do not stop a new message at a free one: they were stored by two
/// writers who could not see each other (a room's overlay and base), and
/// refusing every later message for them would leave the turn mute for good
/// (Astra on #1411).
pub(crate) fn taken_witness_message_order(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    turn_id: &EntityId,
    incoming: &BTreeSet<u32>,
    exempt: &HashSet<EntityId>,
) -> crate::error::Result<Option<u32>> {
    for row in dbs.port_edges(
        txn,
        turn_id,
        crate::ports::EdgeDirection::In,
        Some(EdgeKind::PartOf),
        None,
    )? {
        let edge = row?;
        if edge.kind != EdgeKind::PartOf {
            return Err(Error::CorruptedIndex("witness turn message edge"));
        }
        let message_id = edge.target;
        // The caller's exact retry already proved this row's canonical body and
        // topology. Do not compare its own slot with itself.
        if exempt.contains(&message_id) {
            continue;
        }
        let raw = dbs
            .port_entity_record(txn, &message_id)?
            .ok_or(Error::CorruptedIndex("witness message edge target"))?;
        if raw.entity_type != ENTITY_TYPE_MESSAGE {
            return Err(Error::CorruptedIndex("witness turn message type"));
        }
        let order = witness_message_order(&raw.body)?;
        if incoming.contains(&order) {
            return Ok(Some(order));
        }
    }
    Ok(None)
}

/// The first order after every MESSAGE a stored TURN holds (0 for a turn not
/// stored yet), so a writer that appends later can give each new message a
/// slot no sibling occupies, whatever positions earlier writes chose.
pub(crate) fn next_witness_message_order(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    turn_id: &EntityId,
) -> MemoryResult<u32> {
    let mut next = 0;
    for row in dbs.port_edges(
        txn,
        turn_id,
        crate::ports::EdgeDirection::In,
        Some(EdgeKind::PartOf),
        None,
    )? {
        let message_id = row?.target;
        let Some(raw) = dbs.port_entity_record(txn, &message_id)? else {
            continue;
        };
        if raw.entity_type == ENTITY_TYPE_MESSAGE {
            next = next.max(witness_message_order(&raw.body)?.saturating_add(1));
        }
    }
    Ok(next)
}

/// Reads the already-validated canonical MESSAGE order for append collision
/// checks. Validation is repeated at this storage boundary so a malformed
/// persisted sibling cannot be treated as an ordinary occupied slot.
pub(crate) fn witness_message_order(body: &[u8]) -> crate::error::Result<u32> {
    // MESSAGE text-plane rows retain immutable axes with a document pointer.
    // Reconstruct an empty canonical content slot solely to validate the order
    // envelope; this is not a writer or text resolver and grants no authority.
    let canonical;
    let body = if let Some(bytes) = message_pointer_order_envelope(body)? {
        canonical = bytes;
        canonical.as_slice()
    } else {
        body
    };
    validate_canonical_witness_message_body(body)?;
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::Record(RecordError::InvalidWitnessMessageBody(
            "MESSAGE order is not canonical",
        ))
    })?;
    let Value::Map(entries) = value else {
        return Err(Error::Record(RecordError::InvalidWitnessMessageBody(
            "MESSAGE order is not canonical",
        )));
    };
    entries
        .into_iter()
        .find_map(|(key, value)| (key.as_str() == Some("order")).then(|| value.as_u64()))
        .flatten()
        .and_then(|order| u32::try_from(order).ok())
        .ok_or(Error::Record(RecordError::InvalidWitnessMessageBody(
            "MESSAGE order is not canonical",
        )))
}

/// The call's ORDER axis, checked as a set (ONE-1686).
///
/// `order` is the position readers sort a turn by, so two messages in one call
/// claiming the same position is not an ordering signal a later reader can
/// resolve — it is two rows fighting for one slot, and which one wins is
/// whatever the reader's sort happens to be stable about. The ceiling door
/// binds each message's own order into its authorization; this is the
/// cross-message half of that axis, and it runs BEFORE the write transaction
/// so the whole call is refused rather than half-written.
///
/// This local pass handles one call in linear time. When the target TURN
/// already exists, the transactional witness paths add a second pass over its
/// persisted `PartOf` children so an append cannot reuse a stored position.
pub(in crate::memory) fn distinct_message_orders(messages: &[WitnessMessage]) -> MemoryResult<()> {
    // The order domain is fixed and small enough for a 1,024-word bitset. This
    // keeps validation deterministic O(messages) even for a call spanning the
    // complete legal domain; rescanning each preceding prefix made that input
    // perform roughly two billion comparisons before opening a transaction.
    const ORDER_WORDS: usize = (MAX_WITNESS_MESSAGE_ORDER as usize + 64) / 64;
    let mut seen = [0_u64; ORDER_WORDS];
    for message in messages {
        if message.order > MAX_WITNESS_MESSAGE_ORDER {
            return Err(MemoryError::bad_request(format!(
                "witness message order {} exceeds the {MAX_WITNESS_MESSAGE_ORDER} ceiling",
                message.order,
            )));
        }
        let word = (message.order / 64) as usize;
        let mask = 1_u64 << (message.order % 64);
        if seen[word] & mask != 0 {
            return Err(MemoryError::bad_request_with(
                format!(
                    "two witnessed messages claim order {} in one turn",
                    message.order
                ),
                &["Give each message in one witness call its own position."],
            ));
        }
        seen[word] |= mask;
    }
    Ok(())
}

/// Pointer-aware metadata validation for sibling-order scans (no document load).
fn message_pointer_order_envelope(body: &[u8]) -> crate::error::Result<Option<Vec<u8>>> {
    let mut input = body;
    let value =
        rmpv::decode::read_value(&mut input).map_err(|_| Error::CorruptedIndex("message body"))?;
    let Value::Map(fields) = value else {
        return Ok(None);
    };
    if !fields
        .iter()
        .any(|(key, _)| key.as_str() == Some("entity_doc_ref"))
    {
        return Ok(None);
    }
    let fail = || {
        Error::Record(RecordError::InvalidWitnessMessageBody(
            "invalid MESSAGE document pointer",
        ))
    };
    if !input.is_empty() {
        return Err(fail());
    }
    let mut keys = HashSet::new();
    for (key, value) in &fields {
        let key = key.as_str().ok_or_else(fail)?;
        if !matches!(
            key,
            "author" | "type" | "metadata" | "is_visible" | "order" | "entity_doc_ref"
        ) || !keys.insert(key)
        {
            return Err(fail());
        }
        if key == "entity_doc_ref" {
            EntityId::from_hex(value.as_str().ok_or_else(fail)?).map_err(|_| fail())?;
        }
    }
    let mut canonical = Vec::new();
    for name in [
        "author",
        "type",
        "content",
        "metadata",
        "is_visible",
        "order",
    ] {
        if name == "content" {
            canonical.push((Value::from(name), Value::from("")));
            continue;
        }
        if let Some((key, value)) = fields.iter().find(|(key, _)| key.as_str() == Some(name)) {
            canonical.push((key.clone(), value.clone()));
        } else if name != "metadata" {
            return Err(fail());
        }
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(canonical)).map_err(|_| fail())?;
    Ok(Some(bytes))
}
