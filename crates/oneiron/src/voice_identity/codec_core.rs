//! Shared MessagePack plumbing plus origin/basis/space/consent/sample encode_/decode_ pairs kept together.

use std::io::Cursor;

use rmpv::Value;

use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};

use super::codec_records::{
    BASIS_KIND_NOTICE, BASIS_KIND_TOGGLE, BASIS_KIND_VERBAL, ORIGIN_KIND_SEGMENT, ORIGIN_KIND_SOLO,
};
use super::math_keys::corrupt_voice_row;
use super::types::{
    VOICE_IDENTITY_SCHEMA_VERSION, VoiceConsentBasis, VoiceConsentEventV1, VoiceConsentState,
    VoiceEmbeddingFamily, VoiceEmbeddingSpaceV1, VoiceEnrollmentOrigin, VoiceEnrollmentSampleV1,
    VoicePrintPurpose,
};

pub(super) const KEY_SCHEMA_VERSION: &str = "schema_version";

pub(super) const KEY_KIND: &str = "kind";

pub(super) const CONSENT_KEYS: [&str; 8] = [
    KEY_SCHEMA_VERSION,
    "event_id",
    "subject_ref",
    "recorded_by_ref",
    "occurred_at",
    "purposes",
    "basis",
    "state",
];

const SPACE_KEYS: [&str; 7] = [
    "family",
    "model_id",
    "model_revision",
    "sample_rate",
    "dimension",
    "preprocessing",
    "space_id",
];

pub(super) const SAMPLE_KEYS: [&str; 8] = [
    KEY_SCHEMA_VERSION,
    "sample_id",
    "source_ref",
    "language",
    "origin",
    "duration_ms",
    "source_sha256",
    "vector",
];

const ORIGIN_SOLO_KEYS: [&str; 3] = [KEY_KIND, "session_ref", "speaker_count"];

const ORIGIN_SEGMENT_KEYS: [&str; 3] = [KEY_KIND, "recording_ref", "segment_id"];

const BASIS_NOTICE_KEYS: [&str; 2] = [KEY_KIND, "notice"];

const BASIS_VERBAL_KEYS: [&str; 5] = [KEY_KIND, "recording_ref", "start_ms", "end_ms", "words"];

const BASIS_TOGGLE_KEYS: [&str; 2] = [KEY_KIND, "surface_ref"];

pub(super) fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(corrupt_voice_row)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(corrupt_voice_row());
        };
        if seen[index] {
            return Err(corrupt_voice_row());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|present| present) {
        Ok(())
    } else {
        Err(corrupt_voice_row())
    }
}

pub(super) fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(corrupt_voice_row)
}

pub(super) fn map_entries(value: &Value) -> Result<&Vec<(Value, Value)>> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(corrupt_voice_row()),
    }
}

pub(super) fn decode_str(value: &Value) -> Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(corrupt_voice_row)
}

pub(super) fn decode_u64(value: &Value) -> Result<u64> {
    value.as_u64().ok_or_else(corrupt_voice_row)
}

fn decode_u32(value: &Value) -> Result<u32> {
    u32::try_from(decode_u64(value)?).map_err(|_| corrupt_voice_row())
}

fn decode_usize(value: &Value) -> Result<usize> {
    usize::try_from(decode_u64(value)?).map_err(|_| corrupt_voice_row())
}

pub(super) fn decode_f32(value: &Value) -> Result<f32> {
    match value {
        Value::F32(inner) if inner.is_finite() => Ok(*inner),
        _ => Err(corrupt_voice_row()),
    }
}

pub(super) fn encode_entity_ref(id: &EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

/// An id is exactly one wire shape: a 16-byte MessagePack BINARY value.
///
/// A MessagePack string of the same length is a second, non-canonical form
/// this module's encoder never emits, so it is a corrupt row rather than an
/// id — the sibling record codecs match `Value::Binary` the same way.
pub(super) fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(corrupt_voice_row());
    };
    let raw: [u8; ENTITY_ID_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| corrupt_voice_row())?;
    EntityId::from_bytes(raw).map_err(|_| corrupt_voice_row())
}

pub(super) fn encode_optional_entity_ref(id: Option<&EntityId>) -> Value {
    id.map_or(Value::Nil, encode_entity_ref)
}

pub(super) fn decode_optional_entity_ref(value: &Value) -> Result<Option<EntityId>> {
    if matches!(value, Value::Nil) {
        Ok(None)
    } else {
        decode_entity_ref(value).map(Some)
    }
}

pub(super) fn encode_vector(vector: &[f32]) -> Value {
    Value::Array(vector.iter().copied().map(Value::F32).collect())
}

pub(super) fn decode_vector(value: &Value) -> Result<Vec<f32>> {
    let items = value.as_array().ok_or_else(corrupt_voice_row)?;
    items.iter().map(decode_f32).collect()
}

pub(super) fn encode_string_list(values: &[String]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|item| Value::from(item.clone()))
            .collect(),
    )
}

pub(super) fn decode_string_list(value: &Value) -> Result<Vec<String>> {
    let items = value.as_array().ok_or_else(corrupt_voice_row)?;
    items.iter().map(decode_str).collect()
}

pub(super) fn encode_schema_version() -> (Value, Value) {
    (
        Value::from(KEY_SCHEMA_VERSION),
        Value::from(VOICE_IDENTITY_SCHEMA_VERSION),
    )
}

pub(super) fn require_schema_version(entries: &[(Value, Value)]) -> Result<()> {
    if decode_u64(required_value(entries, KEY_SCHEMA_VERSION)?)? == VOICE_IDENTITY_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(corrupt_voice_row())
    }
}

pub(super) fn write_body(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value)
        .map_err(|_| Error::InvariantViolation("voice identity record encode failed"))?;
    Ok(out)
}

pub(super) fn read_body(bytes: &[u8]) -> Result<Value> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| corrupt_voice_row())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(corrupt_voice_row());
    }
    Ok(value)
}

fn encode_origin(origin: &VoiceEnrollmentOrigin) -> Value {
    match origin {
        VoiceEnrollmentOrigin::AuthenticatedSoloSession {
            session_ref,
            speaker_count,
        } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(ORIGIN_KIND_SOLO)),
            (
                Value::from(ORIGIN_SOLO_KEYS[1]),
                Value::from(session_ref.clone()),
            ),
            (
                Value::from(ORIGIN_SOLO_KEYS[2]),
                Value::from(u64::from(*speaker_count)),
            ),
        ]),
        VoiceEnrollmentOrigin::ConsentedDiarizedSegment {
            recording_ref,
            segment_id,
        } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(ORIGIN_KIND_SEGMENT)),
            (
                Value::from(ORIGIN_SEGMENT_KEYS[1]),
                Value::from(recording_ref.clone()),
            ),
            (
                Value::from(ORIGIN_SEGMENT_KEYS[2]),
                Value::from(segment_id.clone()),
            ),
        ]),
    }
}

/// Sample rows are written by enrollment and removed wholesale by withdrawal;
/// nothing in the production path re-reads one, so the decode half exists for
/// the round-trip and rejection gates that pin the on-disk shape.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn decode_origin(value: &Value) -> Result<VoiceEnrollmentOrigin> {
    let entries = map_entries(value)?;
    match decode_str(required_value(entries, KEY_KIND)?)?.as_str() {
        ORIGIN_KIND_SOLO => {
            validate_keys(entries, &ORIGIN_SOLO_KEYS)?;
            Ok(VoiceEnrollmentOrigin::AuthenticatedSoloSession {
                session_ref: decode_str(required_value(entries, ORIGIN_SOLO_KEYS[1])?)?,
                speaker_count: decode_u32(required_value(entries, ORIGIN_SOLO_KEYS[2])?)?,
            })
        }
        ORIGIN_KIND_SEGMENT => {
            validate_keys(entries, &ORIGIN_SEGMENT_KEYS)?;
            Ok(VoiceEnrollmentOrigin::ConsentedDiarizedSegment {
                recording_ref: decode_str(required_value(entries, ORIGIN_SEGMENT_KEYS[1])?)?,
                segment_id: decode_str(required_value(entries, ORIGIN_SEGMENT_KEYS[2])?)?,
            })
        }
        _ => Err(corrupt_voice_row()),
    }
}

fn encode_basis(basis: &VoiceConsentBasis) -> Value {
    match basis {
        VoiceConsentBasis::ConversationalNotice { notice } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(BASIS_KIND_NOTICE)),
            (
                Value::from(BASIS_NOTICE_KEYS[1]),
                Value::from(notice.clone()),
            ),
        ]),
        VoiceConsentBasis::VerbalOnRecording {
            recording_ref,
            start_ms,
            end_ms,
            words,
        } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(BASIS_KIND_VERBAL)),
            (
                Value::from(BASIS_VERBAL_KEYS[1]),
                Value::from(recording_ref.clone()),
            ),
            (Value::from(BASIS_VERBAL_KEYS[2]), Value::from(*start_ms)),
            (Value::from(BASIS_VERBAL_KEYS[3]), Value::from(*end_ms)),
            (
                Value::from(BASIS_VERBAL_KEYS[4]),
                Value::from(words.clone()),
            ),
        ]),
        VoiceConsentBasis::SettingsToggle { surface_ref } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(BASIS_KIND_TOGGLE)),
            (
                Value::from(BASIS_TOGGLE_KEYS[1]),
                Value::from(surface_ref.clone()),
            ),
        ]),
    }
}

fn decode_basis(value: &Value) -> Result<VoiceConsentBasis> {
    let entries = map_entries(value)?;
    let basis = match decode_str(required_value(entries, KEY_KIND)?)?.as_str() {
        BASIS_KIND_NOTICE => {
            validate_keys(entries, &BASIS_NOTICE_KEYS)?;
            VoiceConsentBasis::ConversationalNotice {
                notice: decode_str(required_value(entries, BASIS_NOTICE_KEYS[1])?)?,
            }
        }
        BASIS_KIND_VERBAL => {
            validate_keys(entries, &BASIS_VERBAL_KEYS)?;
            VoiceConsentBasis::VerbalOnRecording {
                recording_ref: decode_str(required_value(entries, BASIS_VERBAL_KEYS[1])?)?,
                start_ms: decode_u64(required_value(entries, BASIS_VERBAL_KEYS[2])?)?,
                end_ms: decode_u64(required_value(entries, BASIS_VERBAL_KEYS[3])?)?,
                words: decode_str(required_value(entries, BASIS_VERBAL_KEYS[4])?)?,
            }
        }
        BASIS_KIND_TOGGLE => {
            validate_keys(entries, &BASIS_TOGGLE_KEYS)?;
            VoiceConsentBasis::SettingsToggle {
                surface_ref: decode_str(required_value(entries, BASIS_TOGGLE_KEYS[1])?)?,
            }
        }
        _ => return Err(corrupt_voice_row()),
    };
    basis.validate().map_err(|_| corrupt_voice_row())?;
    Ok(basis)
}

pub(super) fn encode_space(space: &VoiceEmbeddingSpaceV1) -> Value {
    Value::Map(vec![
        (
            Value::from(SPACE_KEYS[0]),
            Value::from(space.family.as_str()),
        ),
        (
            Value::from(SPACE_KEYS[1]),
            Value::from(space.model_id.clone()),
        ),
        (
            Value::from(SPACE_KEYS[2]),
            Value::from(space.model_revision.clone()),
        ),
        (
            Value::from(SPACE_KEYS[3]),
            Value::from(u64::from(space.sample_rate)),
        ),
        (
            Value::from(SPACE_KEYS[4]),
            Value::from(space.dimension as u64),
        ),
        (
            Value::from(SPACE_KEYS[5]),
            Value::from(space.preprocessing.clone()),
        ),
        (
            Value::from(SPACE_KEYS[6]),
            Value::from(space.space_id.clone()),
        ),
    ])
}

pub(super) fn decode_space(value: &Value) -> Result<VoiceEmbeddingSpaceV1> {
    let entries = map_entries(value)?;
    validate_keys(entries, &SPACE_KEYS)?;
    let space = VoiceEmbeddingSpaceV1 {
        family: decode_str(required_value(entries, SPACE_KEYS[0])?)
            .ok()
            .as_deref()
            .and_then(VoiceEmbeddingFamily::parse)
            .ok_or_else(corrupt_voice_row)?,
        model_id: decode_str(required_value(entries, SPACE_KEYS[1])?)?,
        model_revision: decode_str(required_value(entries, SPACE_KEYS[2])?)?,
        sample_rate: decode_u32(required_value(entries, SPACE_KEYS[3])?)?,
        dimension: decode_usize(required_value(entries, SPACE_KEYS[4])?)?,
        preprocessing: decode_str(required_value(entries, SPACE_KEYS[5])?)?,
        space_id: decode_str(required_value(entries, SPACE_KEYS[6])?)?,
    };
    // Law 4: a stored space always re-derives its own id.
    space.validate().map_err(|_| corrupt_voice_row())?;
    Ok(space)
}

pub(super) fn encode_consent_event(event: &VoiceConsentEventV1) -> Result<Vec<u8>> {
    event.validate()?;
    let value = Value::Map(vec![
        encode_schema_version(),
        (
            Value::from(CONSENT_KEYS[1]),
            Value::from(event.event_id.clone()),
        ),
        (
            Value::from(CONSENT_KEYS[2]),
            encode_entity_ref(&event.subject_ref),
        ),
        (
            Value::from(CONSENT_KEYS[3]),
            encode_entity_ref(&event.recorded_by_ref),
        ),
        (Value::from(CONSENT_KEYS[4]), Value::from(event.occurred_at)),
        (
            Value::from(CONSENT_KEYS[5]),
            Value::Array(
                event
                    .purposes
                    .iter()
                    .map(|purpose| Value::from(purpose.as_str()))
                    .collect(),
            ),
        ),
        (Value::from(CONSENT_KEYS[6]), encode_basis(&event.basis)),
        (
            Value::from(CONSENT_KEYS[7]),
            Value::from(event.state.as_str()),
        ),
    ]);
    write_body(&value)
}

pub(super) fn decode_consent_event(bytes: &[u8]) -> Result<VoiceConsentEventV1> {
    let value = read_body(bytes)?;
    let entries = map_entries(&value)?;
    validate_keys(entries, &CONSENT_KEYS)?;
    require_schema_version(entries)?;

    let purposes = required_value(entries, CONSENT_KEYS[5])?
        .as_array()
        .ok_or_else(corrupt_voice_row)?
        .iter()
        .map(|item| {
            item.as_str()
                .and_then(VoicePrintPurpose::parse)
                .ok_or_else(corrupt_voice_row)
        })
        .collect::<Result<Vec<_>>>()?;

    let event = VoiceConsentEventV1 {
        event_id: decode_str(required_value(entries, CONSENT_KEYS[1])?)?,
        subject_ref: decode_entity_ref(required_value(entries, CONSENT_KEYS[2])?)?,
        recorded_by_ref: decode_entity_ref(required_value(entries, CONSENT_KEYS[3])?)?,
        occurred_at: decode_u64(required_value(entries, CONSENT_KEYS[4])?)?,
        purposes,
        basis: decode_basis(required_value(entries, CONSENT_KEYS[6])?)?,
        state: decode_str(required_value(entries, CONSENT_KEYS[7])?)
            .ok()
            .as_deref()
            .and_then(VoiceConsentState::parse)
            .ok_or_else(corrupt_voice_row)?,
    };
    event.validate().map_err(|_| corrupt_voice_row())?;
    Ok(event)
}

pub(super) fn encode_sample(sample: &VoiceEnrollmentSampleV1) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        encode_schema_version(),
        (
            Value::from(SAMPLE_KEYS[1]),
            Value::from(sample.sample_id.clone()),
        ),
        (
            Value::from(SAMPLE_KEYS[2]),
            Value::from(sample.source_ref.clone()),
        ),
        (
            Value::from(SAMPLE_KEYS[3]),
            Value::from(sample.language.clone()),
        ),
        (Value::from(SAMPLE_KEYS[4]), encode_origin(&sample.origin)),
        (Value::from(SAMPLE_KEYS[5]), Value::from(sample.duration_ms)),
        (
            Value::from(SAMPLE_KEYS[6]),
            Value::from(sample.source_sha256.clone()),
        ),
        (Value::from(SAMPLE_KEYS[7]), encode_vector(&sample.vector)),
    ]);
    write_body(&value)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn decode_sample(bytes: &[u8]) -> Result<VoiceEnrollmentSampleV1> {
    let value = read_body(bytes)?;
    let entries = map_entries(&value)?;
    validate_keys(entries, &SAMPLE_KEYS)?;
    require_schema_version(entries)?;
    Ok(VoiceEnrollmentSampleV1 {
        sample_id: decode_str(required_value(entries, SAMPLE_KEYS[1])?)?,
        source_ref: decode_str(required_value(entries, SAMPLE_KEYS[2])?)?,
        language: decode_str(required_value(entries, SAMPLE_KEYS[3])?)?,
        origin: decode_origin(required_value(entries, SAMPLE_KEYS[4])?)?,
        duration_ms: decode_u64(required_value(entries, SAMPLE_KEYS[5])?)?,
        source_sha256: decode_str(required_value(entries, SAMPLE_KEYS[6])?)?,
        vector: decode_vector(required_value(entries, SAMPLE_KEYS[7])?)?,
    })
}
