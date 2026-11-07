//! Canonical MessagePack encode/decode and field validation helpers.

use std::io::Cursor;

use rmpv::{Value, ValueRef};

use super::record::{
    CONFIDENCE_KEYS, KEY_COMPACT, KEY_CONFIDENCE, KEY_NARRATIVE, KEY_SCHEMA_VERSION,
    KEY_SOURCE_PAGES, KEY_SOURCE_REVISION_PAGES, KEY_STATUS, KEY_SUBJECT_REF, KEY_TEXT,
    MAX_COMPACT_BYTES, MAX_NARRATIVE_BYTES, MAX_TEXT_BYTES, PSYCH_PROFILE_BODY_KEYS,
    PSYCH_PROFILE_SCHEMA_VERSION, PsychProfile, PsychProfileConfidence, PsychProfileSnapshotStatus,
};
use crate::write_envelope::claim_body::unit_interval_f32;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::error::{Error, RecordError, Result};

mod source_pages;
pub use self::source_pages::PSYCH_PROFILE_SOURCE_IDS_PER_CODEC_PAGE;
use self::source_pages::{decode_pages, decode_source, encode_pages, encode_source};

/// What a stored PSYCH_PROFILE body's envelope says, read before its payload
/// is decoded (FIX 11766).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsychProfileBodyEnvelope {
    /// The current schema: every source carries the exact words it was
    /// read from.
    Current,
    /// An earlier schema, whose sources carry no exact words. No reader
    /// decodes its payload.
    WithoutSourceWords,
}

/// The schema `bytes`, a stored PSYCH_PROFILE body, names, judged from its
/// `schemaVersion` alone: no other field is decoded or validated. A body
/// with no single integer `schemaVersion`, or one past the current schema,
/// is refused.
pub fn psych_profile_body_envelope(bytes: &[u8]) -> Result<PsychProfileBodyEnvelope> {
    let mut cursor = bytes;
    let Ok(ValueRef::Map(entries)) = rmpv::decode::read_value_ref(&mut cursor) else {
        return Err(invalid_profile("body must be a MessagePack map"));
    };
    let mut versions = entries.iter().filter_map(|(key, value)| match key {
        ValueRef::String(key) if key.as_str() == Some(KEY_SCHEMA_VERSION) => Some(value),
        _ => None,
    });
    let (Some(ValueRef::Integer(version)), None) = (versions.next(), versions.next()) else {
        return Err(invalid_profile("missing required profile field"));
    };
    match version.as_u64() {
        Some(PSYCH_PROFILE_SCHEMA_VERSION) => Ok(PsychProfileBodyEnvelope::Current),
        Some(version) if version < PSYCH_PROFILE_SCHEMA_VERSION => {
            Ok(PsychProfileBodyEnvelope::WithoutSourceWords)
        }
        _ => Err(invalid_profile("unsupported schemaVersion")),
    }
}

/// Encodes a PsychProfile body in canonical MessagePack field order. A
/// profile any of whose source revisions lacks the exact words it was read
/// from is refused (FIX 11766).
pub fn encode_psych_profile_body(profile: &PsychProfile) -> Result<Vec<u8>> {
    profile.validate()?;
    profile.validate_source_words()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(PSYCH_PROFILE_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_SUBJECT_REF),
            Value::from(profile.subject_ref.to_hex()),
        ),
        (
            Value::from(KEY_COMPACT),
            Value::from(profile.compact.as_str()),
        ),
        (Value::from(KEY_TEXT), Value::from(profile.text.as_str())),
        (
            Value::from(KEY_NARRATIVE),
            Value::from(profile.narrative.as_str()),
        ),
        (
            Value::from(KEY_SOURCE_REVISION_PAGES),
            encode_pages(&profile.source_revision_ids, |id| Value::from(id.to_hex())),
        ),
        (
            Value::from(KEY_CONFIDENCE),
            encode_confidence(profile.confidence),
        ),
        (
            Value::from(KEY_STATUS),
            Value::from(profile.status.as_code()),
        ),
        (
            Value::from(KEY_SOURCE_PAGES),
            encode_pages(&profile.sources, encode_source),
        ),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("psych profile body MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes and validates a PsychProfile body.
pub fn decode_psych_profile_body(bytes: &[u8]) -> Result<PsychProfile> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_profile("body"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_profile("trailing bytes after body map"));
    }
    decode_psych_profile_value(&value)
}

pub fn validate_psych_profile_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_psych_profile_body(bytes).map(|_| ())
}

fn decode_psych_profile_value(value: &Value) -> Result<PsychProfile> {
    let Value::Map(entries) = value else {
        return Err(invalid_profile("body must be a MessagePack map"));
    };
    validate_keys(entries, &PSYCH_PROFILE_BODY_KEYS)?;
    // The schema is judged before any other field: an earlier schema's
    // payload is never decoded (FIX 11766).
    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64() != Some(PSYCH_PROFILE_SCHEMA_VERSION) {
        return Err(invalid_profile("unsupported schemaVersion"));
    }

    let profile = PsychProfile {
        subject_ref: decode_entity_ref(required_value(entries, KEY_SUBJECT_REF)?)?,
        compact: decode_text_field(
            required_value(entries, KEY_COMPACT)?,
            MAX_COMPACT_BYTES,
            "compact profile tier must be non-empty and at most 4096 bytes",
        )?,
        text: decode_text_field(
            required_value(entries, KEY_TEXT)?,
            MAX_TEXT_BYTES,
            "text profile tier must be non-empty and at most 32768 bytes",
        )?,
        narrative: decode_text_field(
            required_value(entries, KEY_NARRATIVE)?,
            MAX_NARRATIVE_BYTES,
            "narrative profile tier must be non-empty and at most 32768 bytes",
        )?,
        source_revision_ids: decode_pages(
            required_value(entries, KEY_SOURCE_REVISION_PAGES)?,
            "sourceRevisionPages must be full pages of revision ids",
            decode_entity_ref,
        )?,
        confidence: decode_confidence(required_value(entries, KEY_CONFIDENCE)?)?,
        status: required_value(entries, KEY_STATUS)?
            .as_u64()
            .and_then(PsychProfileSnapshotStatus::parse_code)
            .ok_or_else(|| invalid_profile("status must be typed code 1 or 2"))?,
        sources: decode_pages(
            required_value(entries, KEY_SOURCE_PAGES)?,
            "sourcePages must be full pages of sources",
            decode_source,
        )?,
    };

    profile.validate()?;
    profile.validate_source_words()?;
    Ok(profile)
}

pub fn canonical_source_revision_ids(mut ids: Vec<EntityId>) -> Result<Vec<EntityId>> {
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        return Err(invalid_profile(
            "sourceRevisionIds must contain at least one revision id",
        ));
    }
    Ok(ids)
}

pub fn canonical_revision_refs_allow_empty(ids: &[EntityId]) -> Vec<EntityId> {
    let mut ids = ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    ids
}

pub fn canonical_expected_source_revision_ids(mut ids: Vec<EntityId>) -> Vec<EntityId> {
    ids.sort_unstable();
    ids.dedup();
    ids
}

pub fn encode_confidence(confidence: PsychProfileConfidence) -> Value {
    Value::Map(vec![
        (
            Value::from(CONFIDENCE_KEYS[0]),
            Value::F32(confidence.compact),
        ),
        (Value::from(CONFIDENCE_KEYS[1]), Value::F32(confidence.text)),
        (
            Value::from(CONFIDENCE_KEYS[2]),
            Value::F32(confidence.narrative),
        ),
    ])
}

fn decode_confidence(value: &Value) -> Result<PsychProfileConfidence> {
    let Value::Map(entries) = value else {
        return Err(invalid_profile("confidence must be a MessagePack map"));
    };
    validate_keys(entries, &CONFIDENCE_KEYS)?;
    PsychProfileConfidence::new(
        decode_confidence_value(required_value(entries, CONFIDENCE_KEYS[0])?, "compact")?,
        decode_confidence_value(required_value(entries, CONFIDENCE_KEYS[1])?, "text")?,
        decode_confidence_value(required_value(entries, CONFIDENCE_KEYS[2])?, "narrative")?,
    )
}

fn decode_confidence_value(value: &Value, field: &'static str) -> Result<f32> {
    let Some(score) = unit_interval_f32(value) else {
        return Err(match field {
            "compact" => invalid_profile("compact confidence must be finite in [0, 1]"),
            "text" => invalid_profile("text confidence must be finite in [0, 1]"),
            "narrative" => invalid_profile("narrative confidence must be finite in [0, 1]"),
            _ => invalid_profile("confidence must be finite in [0, 1]"),
        });
    };
    Ok(score)
}

fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value
        .as_str()
        .ok_or_else(|| invalid_profile("entity refs must be hex strings"))?;
    EntityId::from_hex(hex).map_err(|_| invalid_profile("entity refs must be valid entity ids"))
}

fn decode_text_field(value: &Value, max_bytes: usize, context: &'static str) -> Result<String> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid_profile("profile tier must be a UTF-8 string"))?;
    validate_text(text, max_bytes, context)?;
    Ok(text.to_owned())
}

pub fn validate_text(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > max_bytes {
        return Err(invalid_profile(context));
    }
    Ok(())
}

pub fn validate_confidence(value: f32, context: &'static str) -> Result<()> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(invalid_profile(context))
    }
}

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key
            .as_str()
            .ok_or_else(|| invalid_profile("body keys must be strings"))?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_profile(
                "body key is not in the pinned PSYCH_PROFILE_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(invalid_profile("duplicate body key"));
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_profile("missing required profile field"))
    }
}

pub fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(entry_key, value)| (entry_key.as_str() == Some(key)).then_some(value))
        .ok_or_else(|| invalid_profile("missing required profile field"))
}

pub fn invalid_profile(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidPsychProfileBody(reason))
}
