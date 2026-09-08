//! Export-body msgpack codec, row-id and fingerprint validators, decode helpers.

use std::collections::BTreeSet;
use std::io::Cursor;

use rmpv::Value;

use super::types::{
    FINGERPRINT_HEX_LEN, KEY_ARTIFACT_FINGERPRINT, KEY_AUDIENCE_REF, KEY_COMPILED_AT_SECS,
    KEY_COMPILED_FINGERPRINT, KEY_EXPORTED_AT_SECS, KEY_GRANTED_AT_SECS, KEY_GRANTED_BY,
    KEY_IDENTITY_LINE, KEY_INCLUDED_ROW_IDS, KEY_SCHEMA_VERSION, KEY_STALE_AFTER_SECS,
    KEY_STRUCK_ROW_IDS, KEY_SUBJECT_REF, KEY_TAKES_INCLUDED, PERSONA_SNAPSHOT_EXPORT_BODY_KEYS,
    PERSONA_SNAPSHOT_EXPORT_SCHEMA_VERSION, PersonaSnapshotExportRecord,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};

pub(super) fn validate_fingerprint_hex(fingerprint: &str) -> Result<()> {
    if fingerprint.len() == FINGERPRINT_HEX_LEN
        && fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(invalid_snapshot(
            "fingerprints must be 64-char lowercase hex",
        ))
    }
}

pub(super) fn validate_row_id_list(row_ids: &[String], context: &'static str) -> Result<()> {
    let mut seen = BTreeSet::new();
    for row_id in row_ids {
        if row_id.is_empty() {
            return Err(invalid_snapshot(match context {
                "includedRowIds" => "includedRowIds entries must be non-empty",
                _ => "struckRowIds entries must be non-empty",
            }));
        }
        if !seen.insert(row_id.as_str()) {
            return Err(invalid_snapshot(match context {
                "includedRowIds" => "includedRowIds entries must be unique",
                _ => "struckRowIds entries must be unique",
            }));
        }
    }
    Ok(())
}

/// Encodes a PERSONA_SNAPSHOT_EXPORT body in canonical MessagePack field order.
pub fn encode_persona_snapshot_export_body(
    record: &PersonaSnapshotExportRecord,
) -> Result<Vec<u8>> {
    record.validate()?;
    let audience_ref = record
        .audience_ref
        .as_deref()
        .map_or(Value::Nil, Value::from);
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(PERSONA_SNAPSHOT_EXPORT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_SUBJECT_REF),
            Value::from(record.subject_ref.to_hex()),
        ),
        (Value::from(KEY_AUDIENCE_REF), audience_ref),
        (
            Value::from(KEY_IDENTITY_LINE),
            Value::from(record.identity_line.as_str()),
        ),
        (
            Value::from(KEY_COMPILED_AT_SECS),
            Value::from(record.compiled_at_secs),
        ),
        (
            Value::from(KEY_STALE_AFTER_SECS),
            Value::from(record.stale_after_secs),
        ),
        (
            Value::from(KEY_COMPILED_FINGERPRINT),
            Value::from(record.compiled_fingerprint.as_str()),
        ),
        (
            Value::from(KEY_TAKES_INCLUDED),
            Value::from(record.takes_included),
        ),
        (
            Value::from(KEY_GRANTED_BY),
            Value::from(record.granted_by.as_str()),
        ),
        (
            Value::from(KEY_GRANTED_AT_SECS),
            Value::from(record.granted_at_secs),
        ),
        (
            Value::from(KEY_EXPORTED_AT_SECS),
            Value::from(record.exported_at_secs),
        ),
        (
            Value::from(KEY_INCLUDED_ROW_IDS),
            encode_row_ids(&record.included_row_ids),
        ),
        (
            Value::from(KEY_STRUCK_ROW_IDS),
            encode_row_ids(&record.struck_row_ids),
        ),
        (
            Value::from(KEY_ARTIFACT_FINGERPRINT),
            Value::from(record.artifact_fingerprint.as_str()),
        ),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value).map_err(|_| {
        Error::InvariantViolation("persona snapshot export body MessagePack encode failed")
    })?;
    Ok(out)
}

/// Decodes and validates a PERSONA_SNAPSHOT_EXPORT body.
pub fn decode_persona_snapshot_export_body(bytes: &[u8]) -> Result<PersonaSnapshotExportRecord> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_snapshot("body"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_snapshot("trailing bytes after body map"));
    }
    decode_persona_snapshot_export_value(&value)
}

pub(crate) fn validate_persona_snapshot_export_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_persona_snapshot_export_body(bytes).map(|_| ())
}

fn decode_persona_snapshot_export_value(value: &Value) -> Result<PersonaSnapshotExportRecord> {
    let Value::Map(entries) = value else {
        return Err(invalid_snapshot("body must be a MessagePack map"));
    };
    validate_keys(entries, &PERSONA_SNAPSHOT_EXPORT_BODY_KEYS)?;

    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64()
        != Some(PERSONA_SNAPSHOT_EXPORT_SCHEMA_VERSION)
    {
        return Err(invalid_snapshot("unsupported schemaVersion"));
    }

    let record = PersonaSnapshotExportRecord {
        subject_ref: decode_entity_ref(required_value(entries, KEY_SUBJECT_REF)?)?,
        audience_ref: decode_optional_text(required_value(entries, KEY_AUDIENCE_REF)?)?,
        identity_line: decode_text(required_value(entries, KEY_IDENTITY_LINE)?)?,
        compiled_at_secs: decode_u64(required_value(entries, KEY_COMPILED_AT_SECS)?)?,
        stale_after_secs: decode_u64(required_value(entries, KEY_STALE_AFTER_SECS)?)?,
        compiled_fingerprint: decode_text(required_value(entries, KEY_COMPILED_FINGERPRINT)?)?,
        takes_included: required_value(entries, KEY_TAKES_INCLUDED)?
            .as_bool()
            .ok_or_else(|| invalid_snapshot("takesIncluded must be a boolean"))?,
        granted_by: decode_text(required_value(entries, KEY_GRANTED_BY)?)?,
        granted_at_secs: decode_u64(required_value(entries, KEY_GRANTED_AT_SECS)?)?,
        exported_at_secs: decode_u64(required_value(entries, KEY_EXPORTED_AT_SECS)?)?,
        included_row_ids: decode_row_ids(required_value(entries, KEY_INCLUDED_ROW_IDS)?)?,
        struck_row_ids: decode_row_ids(required_value(entries, KEY_STRUCK_ROW_IDS)?)?,
        artifact_fingerprint: decode_text(required_value(entries, KEY_ARTIFACT_FINGERPRINT)?)?,
    };

    record.validate()?;
    Ok(record)
}

fn encode_row_ids(row_ids: &[String]) -> Value {
    Value::Array(
        row_ids
            .iter()
            .map(|row_id| Value::from(row_id.as_str()))
            .collect::<Vec<_>>(),
    )
}

fn decode_row_ids(value: &Value) -> Result<Vec<String>> {
    let Value::Array(values) = value else {
        return Err(invalid_snapshot("row id lists must be arrays"));
    };
    values.iter().map(decode_text).collect()
}

fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value
        .as_str()
        .ok_or_else(|| invalid_snapshot("entity refs must be hex strings"))?;
    EntityId::from_hex(hex).map_err(|_| invalid_snapshot("entity refs must be valid entity ids"))
}

fn decode_text(value: &Value) -> Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid_snapshot("field must be a UTF-8 string"))
}

fn decode_optional_text(value: &Value) -> Result<Option<String>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    decode_text(value).map(Some)
}

fn decode_u64(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| invalid_snapshot("field must be an unsigned integer"))
}

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key
            .as_str()
            .ok_or_else(|| invalid_snapshot("body keys must be strings"))?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_snapshot(
                "body key is not in the pinned PERSONA_SNAPSHOT_EXPORT_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(invalid_snapshot("duplicate body key"));
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_snapshot("missing required export record field"))
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(entry_key, value)| (entry_key.as_str() == Some(key)).then_some(value))
        .ok_or_else(|| invalid_snapshot("missing required export record field"))
}

pub(super) fn invalid_snapshot(reason: &'static str) -> Error {
    Error::InvalidPersonaSnapshot(reason)
}

pub(super) fn hash_hex(bytes: &[u8]) -> String {
    bytes_to_hex_lower(blake3::hash(bytes).as_bytes())
}
