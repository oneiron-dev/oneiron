//! Canonical MessagePack encode/decode and field validation helpers.

use std::io::Cursor;

use rmpv::Value;

use super::record::{
    CONFIDENCE_KEYS, KEY_COMPACT, KEY_CONFIDENCE, KEY_NARRATIVE, KEY_SCHEMA_VERSION,
    KEY_SOURCE_REVISION_IDS, KEY_STATUS, KEY_SUBJECT_REF, KEY_TEXT, MAX_COMPACT_BYTES,
    MAX_NARRATIVE_BYTES, MAX_TEXT_BYTES, PSYCH_PROFILE_BODY_KEYS, PSYCH_PROFILE_SCHEMA_VERSION,
    PsychProfile, PsychProfileConfidence, PsychProfileSnapshotStatus,
};
use crate::claim::unit_interval_f32;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Encodes a PsychProfile body in canonical MessagePack field order.
pub fn encode_psych_profile_body(profile: &PsychProfile) -> Result<Vec<u8>> {
    profile.validate()?;
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
            Value::from(KEY_SOURCE_REVISION_IDS),
            encode_source_revision_ids(&profile.source_revision_ids),
        ),
        (
            Value::from(KEY_CONFIDENCE),
            encode_confidence(profile.confidence),
        ),
        (
            Value::from(KEY_STATUS),
            Value::from(profile.status.as_code()),
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

pub(crate) fn validate_psych_profile_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_psych_profile_body(bytes).map(|_| ())
}

fn decode_psych_profile_value(value: &Value) -> Result<PsychProfile> {
    let Value::Map(entries) = value else {
        return Err(invalid_profile("body must be a MessagePack map"));
    };
    validate_keys(entries, &PSYCH_PROFILE_BODY_KEYS)?;

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
        source_revision_ids: decode_source_revision_ids(required_value(
            entries,
            KEY_SOURCE_REVISION_IDS,
        )?)?,
        confidence: decode_confidence(required_value(entries, KEY_CONFIDENCE)?)?,
        status: required_value(entries, KEY_STATUS)?
            .as_u64()
            .and_then(PsychProfileSnapshotStatus::parse_code)
            .ok_or_else(|| invalid_profile("status must be typed code 1 or 2"))?,
    };

    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64() != Some(PSYCH_PROFILE_SCHEMA_VERSION) {
        return Err(invalid_profile("unsupported schemaVersion"));
    }

    profile.validate()?;
    Ok(profile)
}

pub(super) fn encode_source_revision_ids(ids: &[EntityId]) -> Value {
    Value::Array(
        ids.iter()
            .map(|id| Value::from(id.to_hex()))
            .collect::<Vec<_>>(),
    )
}

fn decode_source_revision_ids(value: &Value) -> Result<Vec<EntityId>> {
    let Value::Array(values) = value else {
        return Err(invalid_profile("sourceRevisionIds must be an array"));
    };
    let mut ids = Vec::with_capacity(values.len());
    for value in values {
        ids.push(decode_entity_ref(value)?);
    }
    if ids.is_empty() {
        return Err(invalid_profile(
            "sourceRevisionIds must contain at least one revision id",
        ));
    }
    if !ids.windows(2).all(|ids| ids[0] < ids[1]) {
        return Err(invalid_profile(
            "sourceRevisionIds must be canonical sorted unique ids",
        ));
    }
    Ok(ids)
}

pub(super) fn canonical_source_revision_ids(mut ids: Vec<EntityId>) -> Result<Vec<EntityId>> {
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        return Err(invalid_profile(
            "sourceRevisionIds must contain at least one revision id",
        ));
    }
    Ok(ids)
}

pub(super) fn canonical_revision_refs_allow_empty(ids: &[EntityId]) -> Vec<EntityId> {
    let mut ids = ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    ids
}

pub(super) fn canonical_expected_source_revision_ids(mut ids: Vec<EntityId>) -> Vec<EntityId> {
    ids.sort_unstable();
    ids.dedup();
    ids
}

pub(super) fn encode_confidence(confidence: PsychProfileConfidence) -> Value {
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

pub(super) fn validate_text(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > max_bytes {
        return Err(invalid_profile(context));
    }
    Ok(())
}

pub(super) fn validate_confidence(value: f32, context: &'static str) -> Result<()> {
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

pub(super) fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(entry_key, value)| (entry_key.as_str() == Some(key)).then_some(value))
        .ok_or_else(|| invalid_profile("missing required profile field"))
}

pub(super) fn invalid_profile(reason: &'static str) -> Error {
    Error::InvalidPsychProfileBody(reason)
}
