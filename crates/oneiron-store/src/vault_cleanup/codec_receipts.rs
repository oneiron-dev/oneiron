//! vault_meta row codecs and the digest receipt projector.

use crate::attempt_id::AttemptId;
use crate::receipt_row::ReceiptKind;
use crate::receipt_row::hex_lower;
use crate::vault_cleanup::cleanup_types::CLEANUP_PHASE;
use crate::vault_cleanup::cleanup_types::CleanupCandidate;
use crate::vault_cleanup::cleanup_types::CleanupDecision;
use crate::vault_cleanup::cleanup_types::CleanupDigest;
use crate::vault_cleanup::cleanup_types::CleanupKind;
use crate::vault_cleanup::cleanup_types::CleanupPosture;
use crate::vault_cleanup::cleanup_types::CleanupProposal;
use crate::vault_cleanup::cleanup_types::DIGEST_ROW_LABEL;
use crate::vault_cleanup::cleanup_types::DIGEST_SCHEMA_VERSION;
use crate::vault_cleanup::cleanup_types::FIELD_CLEANUP_ARCHIVED_COUNT;
use crate::vault_cleanup::cleanup_types::FIELD_CLEANUP_ARCHIVED_IDS;
use crate::vault_cleanup::cleanup_types::FIELD_CLEANUP_DECISION;
use crate::vault_cleanup::cleanup_types::FIELD_CLEANUP_PHASE;
use crate::vault_cleanup::cleanup_types::FIELD_CLEANUP_POSTURE;
use crate::vault_cleanup::cleanup_types::FIELD_CLEANUP_PROPOSAL;
use crate::vault_cleanup::cleanup_types::FIELD_CLEANUP_REJECTED_COUNT;
use crate::vault_cleanup::cleanup_types::FIELD_CLEANUP_REJECTED_IDS;
use crate::vault_cleanup::cleanup_types::FIELD_CLEANUP_SKIPPED_COUNT;
use crate::vault_cleanup::cleanup_types::FIELD_CLEANUP_SKIPPED_IDS;
use crate::vault_cleanup::cleanup_types::FIELD_CLEANUP_TOMBSTONE_REASON;
use crate::vault_cleanup::cleanup_types::KEY_ARCHIVED;
use crate::vault_cleanup::cleanup_types::KEY_AT;
use crate::vault_cleanup::cleanup_types::KEY_ATTEMPT;
use crate::vault_cleanup::cleanup_types::KEY_CANDIDATES;
use crate::vault_cleanup::cleanup_types::KEY_CREATED_AT;
use crate::vault_cleanup::cleanup_types::KEY_DECISION;
use crate::vault_cleanup::cleanup_types::KEY_ENTITY;
use crate::vault_cleanup::cleanup_types::KEY_KIND;
use crate::vault_cleanup::cleanup_types::KEY_POSTURE;
use crate::vault_cleanup::cleanup_types::KEY_PROPOSAL;
use crate::vault_cleanup::cleanup_types::KEY_REJECTED;
use crate::vault_cleanup::cleanup_types::KEY_SCHEMA_VERSION;
use crate::vault_cleanup::cleanup_types::KEY_SKIPPED;
use crate::vault_cleanup::cleanup_types::PROPOSAL_ROW_LABEL;
use crate::vault_cleanup::cleanup_types::PROPOSAL_SCHEMA_VERSION;
use crate::vault_cleanup::cleanup_types::VAULT_CLEANUP_ACTOR;
use crate::vault_cleanup::cleanup_types::VAULT_CLEANUP_RECEIPT_PREFIX;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;
use std::collections::BTreeMap;

pub fn encode_row(row: &Value, label: &'static str) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, row).map_err(|_| Error::CorruptedIndex(label))?;
    Ok(encoded)
}

pub fn decode_row(raw: &[u8], label: &'static str) -> Result<Vec<(Value, Value)>> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| Error::CorruptedIndex(label))?;
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(Error::CorruptedIndex(label)),
    }
}

pub fn field<'a>(entries: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
}

/// A stored id list read back, slot by slot; nil is a slot an erase reached
/// (FIX 7517).
pub fn id_list(
    entries: &[(Value, Value)],
    name: &str,
    label: &'static str,
) -> Result<Vec<Option<EntityId>>> {
    let Some(Value::Array(items)) = field(entries, name) else {
        return Err(Error::CorruptedIndex(label));
    };
    items
        .iter()
        .map(|item| match item {
            Value::Nil => Ok(None),
            item => item
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .map(Some)
                .ok_or(Error::CorruptedIndex(label)),
        })
        .collect()
}

/// An id list as stored: each id as hex, an erased slot as nil.
pub fn id_value_list(ids: &[Option<EntityId>]) -> Value {
    Value::Array(
        ids.iter()
            .map(|id| match id {
                Some(id) => Value::from(id.to_hex()),
                None => Value::Nil,
            })
            .collect(),
    )
}

/// One candidate slot as stored: its entity and kind, or nil for a slot an
/// erase reached (FIX 7517).
pub fn candidate_value(candidate: Option<&CleanupCandidate>) -> Value {
    candidate.map_or(Value::Nil, |candidate| {
        Value::Map(vec![
            (
                Value::from(KEY_ENTITY),
                Value::from(candidate.entity.to_hex()),
            ),
            (Value::from(KEY_KIND), Value::from(candidate.kind.as_str())),
        ])
    })
}

/// A stored candidate slot read back; `None` for an erased one.
pub fn candidate_slot(item: &Value, label: &'static str) -> Result<Option<CleanupCandidate>> {
    let fields = match item {
        Value::Nil => return Ok(None),
        Value::Map(fields) => fields,
        _ => return Err(Error::CorruptedIndex(label)),
    };
    let entity = field(fields, KEY_ENTITY)
        .and_then(Value::as_str)
        .and_then(|hex| EntityId::from_hex(hex).ok())
        .ok_or(Error::CorruptedIndex(label))?;
    let kind = field(fields, KEY_KIND)
        .and_then(Value::as_str)
        .and_then(CleanupKind::parse)
        .ok_or(Error::CorruptedIndex(label))?;
    Ok(Some(CleanupCandidate { entity, kind }))
}

pub fn decode_proposal(id: EntityId, raw: &[u8]) -> Result<CleanupProposal> {
    let entries = decode_row(raw, PROPOSAL_ROW_LABEL)?;
    if field(&entries, KEY_SCHEMA_VERSION).and_then(Value::as_u64) != Some(PROPOSAL_SCHEMA_VERSION)
    {
        return Err(Error::CorruptedIndex(PROPOSAL_ROW_LABEL));
    }
    let attempt = field(&entries, KEY_ATTEMPT)
        .and_then(Value::as_str)
        .and_then(hex_to_bytes_16)
        .ok_or(Error::CorruptedIndex(PROPOSAL_ROW_LABEL))?;
    let created_at = field(&entries, KEY_CREATED_AT)
        .and_then(Value::as_u64)
        .ok_or(Error::CorruptedIndex(PROPOSAL_ROW_LABEL))?;
    let Some(Value::Array(items)) = field(&entries, KEY_CANDIDATES) else {
        return Err(Error::CorruptedIndex(PROPOSAL_ROW_LABEL));
    };
    let candidates = items
        .iter()
        .map(|item| candidate_slot(item, PROPOSAL_ROW_LABEL))
        .collect::<Result<_>>()?;
    Ok(CleanupProposal {
        id,
        attempt: AttemptId::from_bytes(&attempt)?,
        created_at,
        candidates,
    })
}

pub fn decode_digest(id: EntityId, raw: &[u8]) -> Result<CleanupDigest> {
    let entries = decode_row(raw, DIGEST_ROW_LABEL)?;
    if field(&entries, KEY_SCHEMA_VERSION).and_then(Value::as_u64) != Some(DIGEST_SCHEMA_VERSION) {
        return Err(Error::CorruptedIndex(DIGEST_ROW_LABEL));
    }
    let attempt = match field(&entries, KEY_ATTEMPT) {
        Some(Value::Nil) | None => None,
        Some(value) => Some(AttemptId::from_bytes(
            &value
                .as_str()
                .and_then(hex_to_bytes_16)
                .ok_or(Error::CorruptedIndex(DIGEST_ROW_LABEL))?,
        )?),
    };
    let proposal = match field(&entries, KEY_PROPOSAL) {
        Some(Value::Nil) | None => None,
        Some(value) => Some(
            value
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or(Error::CorruptedIndex(DIGEST_ROW_LABEL))?,
        ),
    };
    Ok(CleanupDigest {
        id,
        attempt,
        proposal,
        decision: field(&entries, KEY_DECISION)
            .and_then(Value::as_str)
            .and_then(CleanupDecision::parse)
            .ok_or(Error::CorruptedIndex(DIGEST_ROW_LABEL))?,
        posture: field(&entries, KEY_POSTURE)
            .and_then(Value::as_str)
            .and_then(CleanupPosture::parse)
            .ok_or(Error::CorruptedIndex(DIGEST_ROW_LABEL))?,
        at: field(&entries, KEY_AT)
            .and_then(Value::as_u64)
            .ok_or(Error::CorruptedIndex(DIGEST_ROW_LABEL))?,
        archived: id_list(&entries, KEY_ARCHIVED, DIGEST_ROW_LABEL)?,
        skipped: id_list(&entries, KEY_SKIPPED, DIGEST_ROW_LABEL)?,
        rejected: match field(&entries, KEY_REJECTED) {
            None => Vec::new(),
            Some(_) => id_list(&entries, KEY_REJECTED, DIGEST_ROW_LABEL)?,
        },
    })
}

fn hex_to_bytes_16(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0_u8; 16];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The live ids, comma-joined. An erased slot names no one, so it is left
/// out here and kept in the count beside it (FIX 7517).
pub fn join_ids(ids: &[Option<EntityId>]) -> String {
    ids.iter()
        .flatten()
        .map(EntityId::to_hex)
        .collect::<Vec<_>>()
        .join(",")
}
