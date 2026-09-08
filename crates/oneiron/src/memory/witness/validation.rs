//! Idempotency validators: turn/message existence, parent/actor binding, order collision axes.

use super::super::*;
use super::decode_witness_turn_speaker;

use std::collections::HashSet;

use rmpv::Value;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::{MAX_WITNESS_MESSAGE_ORDER, validate_canonical_witness_message_body};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::store::ManifestDbs;

/// Returns the one target an existing structural edge kind names. More than
/// one target is already a re-parented row and therefore fails closed.
pub(crate) fn sole_edge_target(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    source: &EntityId,
    kind: EdgeKind,
    label: &'static str,
) -> MemoryResult<Option<EntityId>> {
    let prefix = crate::vault::edge_kind_prefix(source, kind);
    let mut target = None;
    for row in dbs.edges_out().prefix_iter(txn, &prefix)? {
        let (key, _) = row?;
        let (_, _, candidate) = crate::edge::parse_strict_edge_record_key(&key)?;
        if target.replace(candidate).is_some() {
            return Err(MemoryError::bad_request(format!(
                "an existing witnessed {label} has more than one {kind:?} parent"
            )));
        }
    }
    Ok(target)
}

/// Checks whether a deterministic TURN already exists and, when it does,
/// proves that retrying it cannot move it under another conversation or
/// speaker.
pub(super) fn validate_existing_witness_turn(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    turn_id: &EntityId,
    conversation_id: &EntityId,
    incoming_speaker: Option<&str>,
) -> MemoryResult<bool> {
    let Some(raw) = dbs.entities().get(txn, turn_id.as_bytes())? else {
        return Ok(false);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_TURN {
        return Err(MemoryError::bad_request(
            "the witnessed turn ref resolves to a non-TURN entity",
        ));
    }
    let stored_speaker = decode_witness_turn_speaker(&raw[ENTITY_METADATA_HEADER_LEN..])?;
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
    Ok(true)
}

/// Checks whether a deterministic MESSAGE already exists. Its canonical body
/// and all three structural bindings are immutable together: exact retries are
/// no-ops, while changed text/kind/order/visibility or a new parent/actor is a
/// refusal rather than an overwrite or a second edge.
#[expect(
    clippy::too_many_arguments,
    reason = "body, turn, conversation, author, and actor are distinct immutable bindings of one existing MESSAGE"
)]
pub(super) fn validate_existing_witness_message(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    message_id: &EntityId,
    body: &[u8],
    turn_id: &EntityId,
    conversation_id: &EntityId,
    author: WitnessAuthor,
    actor: &EntityId,
) -> MemoryResult<bool> {
    let Some(raw) = dbs.entities().get(txn, message_id.as_bytes())? else {
        return Ok(false);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_MESSAGE {
        return Err(MemoryError::bad_request(
            "the witnessed message id resolves to a non-MESSAGE entity",
        ));
    }
    if &raw[ENTITY_METADATA_HEADER_LEN..] != body {
        return Err(Error::InvalidWitnessMessageBody(
            "an existing MESSAGE id is bound to its original canonical body",
        )
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
    let expected_author = (author != WitnessAuthor::System).then_some(*actor);
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
    const ORDER_WORDS: usize = (MAX_WITNESS_MESSAGE_ORDER as usize + 64) / 64;
    let mut occupied = [0_u64; ORDER_WORDS];

    // Reserve every incoming slot first. This catches a collision with a
    // persisted sibling while still allowing an exact retry's own id below.
    for message in messages {
        if message.order > MAX_WITNESS_MESSAGE_ORDER {
            return Err(MemoryError::bad_request(format!(
                "witness message order {} exceeds the {MAX_WITNESS_MESSAGE_ORDER} ceiling",
                message.order,
            )));
        }
        let word = (message.order / 64) as usize;
        occupied[word] |= 1_u64 << (message.order % 64);
    }

    let prefix = crate::vault::edge_kind_prefix(turn_id, EdgeKind::PartOf);
    for row in dbs.edges_in().prefix_iter(txn, &prefix)? {
        let (key, value) = row?;
        let edge = crate::edge::parse_strict_edge_record(&key, &value)?;
        if edge.source != *turn_id || edge.kind != EdgeKind::PartOf {
            return Err(Error::CorruptedIndex("witness turn message edge").into());
        }
        let message_id = edge.target;
        // The caller's exact retry already proved this row's canonical body and
        // topology. Do not compare its own slot with itself.
        if existing_message_ids.contains(&message_id) {
            continue;
        }
        let raw = dbs
            .entities()
            .get(txn, message_id.as_bytes())?
            .ok_or(Error::CorruptedIndex("witness message edge target"))?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("witness message header"))?;
        if header.entity_type != ENTITY_TYPE_MESSAGE {
            return Err(Error::CorruptedIndex("witness turn message type").into());
        }
        let order = canonical_witness_message_order(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let word = (order / 64) as usize;
        let mask = 1_u64 << (order % 64);
        if occupied[word] & mask != 0 {
            return Err(MemoryError::bad_request_with(
                format!(
                    "witness message order {order} collides with an existing message in this turn"
                ),
                &["Give each message in a turn its own position."],
            ));
        }
        occupied[word] |= mask;
    }
    Ok(())
}

/// Reads the already-validated canonical MESSAGE order for append collision
/// checks. Validation is repeated at this storage boundary so a malformed
/// persisted sibling cannot be treated as an ordinary occupied slot.
fn canonical_witness_message_order(body: &[u8]) -> MemoryResult<u32> {
    validate_canonical_witness_message_body(body)?;
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidWitnessMessageBody("MESSAGE order is not canonical"))?;
    let Value::Map(entries) = value else {
        return Err(Error::InvalidWitnessMessageBody("MESSAGE order is not canonical").into());
    };
    entries
        .into_iter()
        .find_map(|(key, value)| (key.as_str() == Some("order")).then(|| value.as_u64()))
        .flatten()
        .and_then(|order| u32::try_from(order).ok())
        .ok_or_else(|| Error::InvalidWitnessMessageBody("MESSAGE order is not canonical").into())
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
pub(crate) fn distinct_message_orders(messages: &[WitnessMessage]) -> MemoryResult<()> {
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
