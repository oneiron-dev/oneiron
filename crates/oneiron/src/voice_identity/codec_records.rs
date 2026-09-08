//! Print/evidence/segment/roster encode_/decode_ pairs; roster pair is the interlocutor-seam wire shape.

use rmpv::Value;

use crate::error::Result;

use super::codec_core::{
    KEY_KIND, KEY_SCHEMA_VERSION, decode_entity_ref, decode_f32, decode_optional_entity_ref,
    decode_space, decode_str, decode_string_list, decode_u64, decode_vector, encode_entity_ref,
    encode_optional_entity_ref, encode_schema_version, encode_space, encode_string_list,
    encode_vector, map_entries, read_body, require_schema_version, required_value, validate_keys,
    write_body,
};
use super::math_keys::{corrupt_voice_row, validate_voice_vector};
use super::types::{
    VoiceAttributionEvidence, VoicePrintCalibration, VoicePrintRecordV1, VoiceResolvedSegment,
    VoiceSessionRosterV1,
};

pub(super) const PRINT_KEYS: [&str; 13] = [
    KEY_SCHEMA_VERSION,
    "subject_ref",
    "contact_ref",
    "relationship_ref",
    "consent_event_ref",
    "space",
    "centroid",
    "sample_ids",
    "sample_languages",
    "calibration",
    "created_at",
    "updated_at",
    "delete_after",
];

const ROSTER_KEYS: [&str; 7] = [
    KEY_SCHEMA_VERSION,
    "voice_session_ref",
    "recording_id",
    "embedding_space_id",
    "known_threshold",
    "segments",
    "created_at",
];

const SEGMENT_KEYS: [&str; 7] = [
    "segment_id",
    "start_ms",
    "end_ms",
    "speaker_label",
    "subject_ref",
    "contact_ref",
    "evidence",
];

const EVIDENCE_ENROLLED_KEYS: [&str; 4] = [KEY_KIND, "subject_ref", "score", "calibration"];

const EVIDENCE_INVITE_KEYS: [&str; 2] = [KEY_KIND, "attendee_ref"];

const EVIDENCE_RESIDUAL_KEYS: [&str; 2] = [KEY_KIND, "cluster_ref"];

pub(super) const ORIGIN_KIND_SOLO: &str = "authenticated_solo_session";

pub(super) const ORIGIN_KIND_SEGMENT: &str = "consented_diarized_segment";

pub(super) const BASIS_KIND_NOTICE: &str = "conversational_notice";

pub(super) const BASIS_KIND_VERBAL: &str = "verbal_on_recording";

pub(super) const BASIS_KIND_TOGGLE: &str = "settings_toggle";

const EVIDENCE_KIND_ENROLLED: &str = "enrolled_print";

const EVIDENCE_KIND_INVITE: &str = "invite_elimination";

const EVIDENCE_KIND_RESIDUAL: &str = "residual_cluster";

pub(super) fn encode_print_record(record: &VoicePrintRecordV1) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        encode_schema_version(),
        (
            Value::from(PRINT_KEYS[1]),
            encode_entity_ref(&record.subject_ref),
        ),
        (
            Value::from(PRINT_KEYS[2]),
            encode_optional_entity_ref(record.contact_ref.as_ref()),
        ),
        (
            Value::from(PRINT_KEYS[3]),
            encode_optional_entity_ref(record.relationship_ref.as_ref()),
        ),
        (
            Value::from(PRINT_KEYS[4]),
            Value::from(record.consent_event_ref.clone()),
        ),
        (Value::from(PRINT_KEYS[5]), encode_space(&record.space)),
        (Value::from(PRINT_KEYS[6]), encode_vector(&record.centroid)),
        (
            Value::from(PRINT_KEYS[7]),
            encode_string_list(&record.sample_ids),
        ),
        (
            Value::from(PRINT_KEYS[8]),
            encode_string_list(&record.sample_languages),
        ),
        (
            Value::from(PRINT_KEYS[9]),
            Value::from(record.calibration.as_str()),
        ),
        (Value::from(PRINT_KEYS[10]), Value::from(record.created_at)),
        (Value::from(PRINT_KEYS[11]), Value::from(record.updated_at)),
        (
            Value::from(PRINT_KEYS[12]),
            record.delete_after.map_or(Value::Nil, Value::from),
        ),
    ]);
    write_body(&value)
}

pub(super) fn decode_print_record(bytes: &[u8]) -> Result<VoicePrintRecordV1> {
    let value = read_body(bytes)?;
    let entries = map_entries(&value)?;
    validate_keys(entries, &PRINT_KEYS)?;
    require_schema_version(entries)?;

    let space = decode_space(required_value(entries, PRINT_KEYS[5])?)?;
    let centroid = decode_vector(required_value(entries, PRINT_KEYS[6])?)?;
    validate_voice_vector(&centroid, space.dimension).map_err(|_| corrupt_voice_row())?;

    let delete_after_value = required_value(entries, PRINT_KEYS[12])?;
    let delete_after = if matches!(delete_after_value, Value::Nil) {
        None
    } else {
        Some(decode_u64(delete_after_value)?)
    };

    Ok(VoicePrintRecordV1 {
        subject_ref: decode_entity_ref(required_value(entries, PRINT_KEYS[1])?)?,
        contact_ref: decode_optional_entity_ref(required_value(entries, PRINT_KEYS[2])?)?,
        relationship_ref: decode_optional_entity_ref(required_value(entries, PRINT_KEYS[3])?)?,
        consent_event_ref: decode_str(required_value(entries, PRINT_KEYS[4])?)?,
        space,
        centroid,
        sample_ids: decode_string_list(required_value(entries, PRINT_KEYS[7])?)?,
        sample_languages: decode_string_list(required_value(entries, PRINT_KEYS[8])?)?,
        calibration: decode_str(required_value(entries, PRINT_KEYS[9])?)
            .ok()
            .as_deref()
            .and_then(VoicePrintCalibration::parse)
            .ok_or_else(corrupt_voice_row)?,
        created_at: decode_u64(required_value(entries, PRINT_KEYS[10])?)?,
        updated_at: decode_u64(required_value(entries, PRINT_KEYS[11])?)?,
        delete_after,
    })
}

fn encode_evidence(evidence: &VoiceAttributionEvidence) -> Value {
    match evidence {
        VoiceAttributionEvidence::EnrolledPrint {
            subject_ref,
            score,
            calibration,
        } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(EVIDENCE_KIND_ENROLLED)),
            (
                Value::from(EVIDENCE_ENROLLED_KEYS[1]),
                encode_entity_ref(subject_ref),
            ),
            (Value::from(EVIDENCE_ENROLLED_KEYS[2]), Value::F32(*score)),
            (
                Value::from(EVIDENCE_ENROLLED_KEYS[3]),
                Value::from(calibration.as_str()),
            ),
        ]),
        VoiceAttributionEvidence::InviteElimination { attendee_ref } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(EVIDENCE_KIND_INVITE)),
            (
                Value::from(EVIDENCE_INVITE_KEYS[1]),
                encode_entity_ref(attendee_ref),
            ),
        ]),
        VoiceAttributionEvidence::ResidualCluster { cluster_ref } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(EVIDENCE_KIND_RESIDUAL)),
            (
                Value::from(EVIDENCE_RESIDUAL_KEYS[1]),
                Value::from(cluster_ref.clone()),
            ),
        ]),
    }
}

fn decode_evidence(value: &Value) -> Result<VoiceAttributionEvidence> {
    let entries = map_entries(value)?;
    match decode_str(required_value(entries, KEY_KIND)?)?.as_str() {
        EVIDENCE_KIND_ENROLLED => {
            validate_keys(entries, &EVIDENCE_ENROLLED_KEYS)?;
            Ok(VoiceAttributionEvidence::EnrolledPrint {
                subject_ref: decode_entity_ref(required_value(
                    entries,
                    EVIDENCE_ENROLLED_KEYS[1],
                )?)?,
                score: decode_f32(required_value(entries, EVIDENCE_ENROLLED_KEYS[2])?)?,
                calibration: decode_str(required_value(entries, EVIDENCE_ENROLLED_KEYS[3])?)
                    .ok()
                    .as_deref()
                    .and_then(VoicePrintCalibration::parse)
                    .ok_or_else(corrupt_voice_row)?,
            })
        }
        EVIDENCE_KIND_INVITE => {
            validate_keys(entries, &EVIDENCE_INVITE_KEYS)?;
            Ok(VoiceAttributionEvidence::InviteElimination {
                attendee_ref: decode_entity_ref(required_value(entries, EVIDENCE_INVITE_KEYS[1])?)?,
            })
        }
        EVIDENCE_KIND_RESIDUAL => {
            validate_keys(entries, &EVIDENCE_RESIDUAL_KEYS)?;
            Ok(VoiceAttributionEvidence::ResidualCluster {
                cluster_ref: decode_str(required_value(entries, EVIDENCE_RESIDUAL_KEYS[1])?)?,
            })
        }
        _ => Err(corrupt_voice_row()),
    }
}

fn encode_resolved_segment(segment: &VoiceResolvedSegment) -> Value {
    Value::Map(vec![
        (
            Value::from(SEGMENT_KEYS[0]),
            Value::from(segment.segment_id.clone()),
        ),
        (Value::from(SEGMENT_KEYS[1]), Value::from(segment.start_ms)),
        (Value::from(SEGMENT_KEYS[2]), Value::from(segment.end_ms)),
        (
            Value::from(SEGMENT_KEYS[3]),
            Value::from(segment.speaker_label.clone()),
        ),
        (
            Value::from(SEGMENT_KEYS[4]),
            encode_optional_entity_ref(segment.subject_ref.as_ref()),
        ),
        (
            Value::from(SEGMENT_KEYS[5]),
            encode_optional_entity_ref(segment.contact_ref.as_ref()),
        ),
        (
            Value::from(SEGMENT_KEYS[6]),
            encode_evidence(&segment.evidence),
        ),
    ])
}

fn decode_resolved_segment(value: &Value) -> Result<VoiceResolvedSegment> {
    let entries = map_entries(value)?;
    validate_keys(entries, &SEGMENT_KEYS)?;
    Ok(VoiceResolvedSegment {
        segment_id: decode_str(required_value(entries, SEGMENT_KEYS[0])?)?,
        start_ms: decode_u64(required_value(entries, SEGMENT_KEYS[1])?)?,
        end_ms: decode_u64(required_value(entries, SEGMENT_KEYS[2])?)?,
        speaker_label: decode_str(required_value(entries, SEGMENT_KEYS[3])?)?,
        subject_ref: decode_optional_entity_ref(required_value(entries, SEGMENT_KEYS[4])?)?,
        contact_ref: decode_optional_entity_ref(required_value(entries, SEGMENT_KEYS[5])?)?,
        evidence: decode_evidence(required_value(entries, SEGMENT_KEYS[6])?)?,
    })
}

pub(super) fn encode_roster(roster: &VoiceSessionRosterV1) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        encode_schema_version(),
        (
            Value::from(ROSTER_KEYS[1]),
            Value::from(roster.voice_session_ref.clone()),
        ),
        (
            Value::from(ROSTER_KEYS[2]),
            Value::from(roster.recording_id.clone()),
        ),
        (
            Value::from(ROSTER_KEYS[3]),
            Value::from(roster.embedding_space_id.clone()),
        ),
        (
            Value::from(ROSTER_KEYS[4]),
            Value::F32(roster.known_threshold),
        ),
        (
            Value::from(ROSTER_KEYS[5]),
            Value::Array(
                roster
                    .segments
                    .iter()
                    .map(encode_resolved_segment)
                    .collect(),
            ),
        ),
        (Value::from(ROSTER_KEYS[6]), Value::from(roster.created_at)),
    ]);
    write_body(&value)
}

pub(super) fn decode_roster(bytes: &[u8]) -> Result<VoiceSessionRosterV1> {
    let value = read_body(bytes)?;
    let entries = map_entries(&value)?;
    validate_keys(entries, &ROSTER_KEYS)?;
    require_schema_version(entries)?;
    let segments = required_value(entries, ROSTER_KEYS[5])?
        .as_array()
        .ok_or_else(corrupt_voice_row)?
        .iter()
        .map(decode_resolved_segment)
        .collect::<Result<Vec<_>>>()?;
    Ok(VoiceSessionRosterV1 {
        voice_session_ref: decode_str(required_value(entries, ROSTER_KEYS[1])?)?,
        recording_id: decode_str(required_value(entries, ROSTER_KEYS[2])?)?,
        embedding_space_id: decode_str(required_value(entries, ROSTER_KEYS[3])?)?,
        known_threshold: decode_f32(required_value(entries, ROSTER_KEYS[4])?)?,
        segments,
        created_at: decode_u64(required_value(entries, ROSTER_KEYS[6])?)?,
    })
}
