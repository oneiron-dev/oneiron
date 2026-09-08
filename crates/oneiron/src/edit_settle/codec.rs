//! Row and anchor codec.

use std::io::Cursor;

use rmpv::Value;

use super::keys::{
    BLOB_ARTIFACT_SETTLEMENT_KEY_PREFIX, KEY_ACTOR_REF, KEY_ANCHOR_DRIFTED, KEY_ANCHOR_LOCATOR,
    KEY_ANCHOR_THREAD_ID, KEY_ANCHORS, KEY_BEFORE_VERSION, KEY_BRIEF_REF, KEY_CONTENT_HASH,
    KEY_MANIFEST_OPS, KEY_MANIFEST_REF, KEY_OUTCOME, KEY_PROPOSAL_REF, KEY_REASON,
    KEY_SCHEMA_VERSION, KEY_SETTLED_AT, KEY_VERSION, SETTLE_VERB_CLASS, SETTLEMENT_SCHEMA_VERSION,
};
use super::records::{SettleOutcomeKind, SettledAnchor, SettlementRecord};
use crate::anchored_annotation::{decode_locator, encode_locator};
use crate::consent::{
    ActionClass as ConsentActionClass, ActionEnvelope as ConsentActionEnvelope,
    ActorBound as ConsentActorBound, GrantBound as ConsentGrantBound,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::write_envelope::WriteActor;

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

pub(super) fn settlement_key(artifact_id: &EntityId, proposal_ref: &str) -> Vec<u8> {
    let proposal_hash = blake3::hash(proposal_ref.as_bytes());
    let mut key = Vec::with_capacity(
        BLOB_ARTIFACT_SETTLEMENT_KEY_PREFIX.len() + ENTITY_ID_LEN + proposal_hash.as_bytes().len(),
    );
    key.extend_from_slice(BLOB_ARTIFACT_SETTLEMENT_KEY_PREFIX);
    key.extend_from_slice(artifact_id.as_bytes());
    key.extend_from_slice(proposal_hash.as_bytes());
    key
}

pub(super) fn settlement_key_artifact_id(key: &[u8]) -> Result<EntityId> {
    let start = BLOB_ARTIFACT_SETTLEMENT_KEY_PREFIX.len();
    let end = start + ENTITY_ID_LEN;
    if key.len() != end + 32 || !key.starts_with(BLOB_ARTIFACT_SETTLEMENT_KEY_PREFIX) {
        return Err(Error::CorruptedIndex("blob artifact settlement key"));
    }
    let raw: [u8; ENTITY_ID_LEN] = key[start..end]
        .try_into()
        .map_err(|_| Error::CorruptedIndex("blob artifact settlement key"))?;
    EntityId::from_bytes(raw).map_err(|_| Error::CorruptedIndex("blob artifact settlement key"))
}

// ---------------------------------------------------------------------------
// Codec (pinned-key MessagePack)
// ---------------------------------------------------------------------------

pub(super) fn encode_settlement_record(record: &SettlementRecord) -> Result<Vec<u8>> {
    let anchors: Vec<Value> = record.anchors.iter().map(encode_settled_anchor).collect();
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(SETTLEMENT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_PROPOSAL_REF),
            Value::from(record.proposal_ref.as_str()),
        ),
        (
            Value::from(KEY_OUTCOME),
            Value::from(record.outcome.as_str()),
        ),
        (Value::from(KEY_SETTLED_AT), Value::from(record.settled_at)),
        (
            Value::from(KEY_ACTOR_REF),
            option_str_value(record.actor_ref.as_deref()),
        ),
        (
            Value::from(KEY_BRIEF_REF),
            option_str_value(record.brief_ref.as_deref()),
        ),
        (
            Value::from(KEY_BEFORE_VERSION),
            record.before_version.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_VERSION),
            record.version.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_CONTENT_HASH),
            record
                .content_hash
                .map_or(Value::Nil, |hash| Value::Binary(hash.to_vec())),
        ),
        (
            Value::from(KEY_MANIFEST_REF),
            record
                .manifest_ref
                .map_or(Value::Nil, |hash| Value::Binary(hash.to_vec())),
        ),
        (
            Value::from(KEY_MANIFEST_OPS),
            Value::from(record.manifest_ops),
        ),
        (Value::from(KEY_ANCHORS), Value::Array(anchors)),
        (
            Value::from(KEY_REASON),
            option_str_value(record.reason.as_deref()),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("settlement record MessagePack encode failed"))?;
    Ok(out)
}

fn encode_settled_anchor(anchor: &SettledAnchor) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_ANCHOR_THREAD_ID),
            Value::Binary(anchor.thread_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_ANCHOR_LOCATOR),
            encode_locator(&anchor.locator),
        ),
        (Value::from(KEY_ANCHOR_DRIFTED), Value::from(anchor.drifted)),
    ])
}

pub(super) fn decode_settlement_record(bytes: &[u8]) -> Result<SettlementRecord> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| corrupt())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(corrupt());
    }
    let Value::Map(entries) = value else {
        return Err(corrupt());
    };
    if field(&entries, KEY_SCHEMA_VERSION).and_then(Value::as_u64)
        != Some(SETTLEMENT_SCHEMA_VERSION)
    {
        return Err(corrupt());
    }
    let outcome =
        SettleOutcomeKind::parse(field_str(&entries, KEY_OUTCOME)?).ok_or_else(corrupt)?;
    let anchors = decode_anchors(field(&entries, KEY_ANCHORS).ok_or_else(corrupt)?)?;
    Ok(SettlementRecord {
        proposal_ref: field_str(&entries, KEY_PROPOSAL_REF)?.to_owned(),
        outcome,
        settled_at: field_u64(&entries, KEY_SETTLED_AT)?,
        actor_ref: field_opt_str(&entries, KEY_ACTOR_REF)?,
        brief_ref: field_opt_str(&entries, KEY_BRIEF_REF)?,
        before_version: field_opt_u64(&entries, KEY_BEFORE_VERSION)?,
        version: field_opt_u64(&entries, KEY_VERSION)?,
        content_hash: field_opt_hash(&entries, KEY_CONTENT_HASH)?,
        manifest_ref: field_opt_hash(&entries, KEY_MANIFEST_REF)?,
        manifest_ops: field_u64(&entries, KEY_MANIFEST_OPS)?,
        anchors,
        reason: field_opt_str(&entries, KEY_REASON)?,
    })
}

fn decode_anchors(value: &Value) -> Result<Vec<SettledAnchor>> {
    let Value::Array(items) = value else {
        return Err(corrupt());
    };
    items.iter().map(decode_settled_anchor).collect()
}

fn decode_settled_anchor(value: &Value) -> Result<SettledAnchor> {
    let Value::Map(entries) = value else {
        return Err(corrupt());
    };
    let thread_id = field_entity(entries, KEY_ANCHOR_THREAD_ID)?;
    let locator = decode_locator(field(entries, KEY_ANCHOR_LOCATOR).ok_or_else(corrupt)?)?;
    let drifted = field(entries, KEY_ANCHOR_DRIFTED)
        .and_then(Value::as_bool)
        .ok_or_else(corrupt)?;
    Ok(SettledAnchor {
        thread_id,
        locator,
        drifted,
    })
}

fn field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(entry_key, _)| entry_key.as_str() == Some(key))
        .map(|(_, value)| value)
}

fn field_str<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    field(entries, key)
        .and_then(Value::as_str)
        .ok_or_else(corrupt)
}

fn field_u64(entries: &[(Value, Value)], key: &str) -> Result<u64> {
    field(entries, key)
        .and_then(Value::as_u64)
        .ok_or_else(corrupt)
}

fn field_opt_str(entries: &[(Value, Value)], key: &str) -> Result<Option<String>> {
    match field(entries, key) {
        None => Err(corrupt()),
        Some(Value::Nil) => Ok(None),
        Some(value) => Ok(Some(value.as_str().ok_or_else(corrupt)?.to_owned())),
    }
}

fn field_opt_u64(entries: &[(Value, Value)], key: &str) -> Result<Option<u64>> {
    match field(entries, key) {
        None => Err(corrupt()),
        Some(Value::Nil) => Ok(None),
        Some(value) => Ok(Some(value.as_u64().ok_or_else(corrupt)?)),
    }
}

fn field_opt_hash(entries: &[(Value, Value)], key: &str) -> Result<Option<[u8; 32]>> {
    match field(entries, key) {
        None => Err(corrupt()),
        Some(Value::Nil) => Ok(None),
        Some(Value::Binary(bytes)) => Ok(Some(bytes.as_slice().try_into().map_err(|_| corrupt())?)),
        Some(_) => Err(corrupt()),
    }
}

fn field_entity(entries: &[(Value, Value)], key: &str) -> Result<EntityId> {
    let Some(Value::Binary(bytes)) = field(entries, key) else {
        return Err(corrupt());
    };
    let raw: [u8; ENTITY_ID_LEN] = bytes.as_slice().try_into().map_err(|_| corrupt())?;
    EntityId::from_bytes(raw).map_err(|_| corrupt())
}

fn option_str_value(value: Option<&str>) -> Value {
    value.map_or(Value::Nil, Value::from)
}

pub(super) fn corrupt() -> Error {
    Error::CorruptedIndex("blob artifact settlement record")
}

/// The exact DEC-0006 bound a standing settle must be covered by:
/// acting actor × [`SETTLE_VERB_CLASS`] × this brief, target-pinned.
///
/// Target-pinning is what makes a wider-target assumption fail: a grant whose
/// envelope does not name this brief does not contain this bound.
pub(super) fn settle_grant_bound(actor: WriteActor, brief_ref: &str) -> Result<ConsentGrantBound> {
    // `brief_ref` is used VERBATIM as both selector and target: the caller's
    // refs already carry their own namespace (`brief:acme`), and re-prefixing
    // here would mint a bound no grant can ever match.
    let brief_ref = brief_ref.trim().to_owned();
    ConsentGrantBound::action(
        ConsentActorBound::new(actor.entity_ref().to_hex())?,
        ConsentActionClass::new(SETTLE_VERB_CLASS)?,
        ConsentActionEnvelope::new([brief_ref.clone()])?.with_target(brief_ref)?,
    )
}
