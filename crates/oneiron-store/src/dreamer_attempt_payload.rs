//! Dreamer attempt payload envelope and its MessagePack codec.
//!
//! The generic attempt queue stores a Dreamer runner attempt's payload as this
//! envelope. The store decodes it without the Dreamer runner; the runner and
//! its other row codecs re-export these items at their old paths.

use std::io::Cursor;

use rmpv::Value;

use crate::attempt_id::AttemptId;
use crate::dreamer_attempt_kind::{
    DREAMER_ATTEMPT_PAYLOAD_KEYS, DREAMER_ATTEMPT_PAYLOAD_SCHEMA_VERSION,
};
use oneiron_base::error::{ArtifactError, Error, Result};

/// Typed Dreamer attempt payload stored in the generic queue row.
#[derive(Debug, Clone, PartialEq)]
pub struct DreamerAttemptPayload {
    pub attempt_type: String,
    pub input: Value,
    pub parent_attempt: Option<AttemptId>,
}

// Storage/wire keys keep the legacy "job" spelling; ONE-1714 renamed code only.
pub const KEY_SCHEMA_VERSION: &str = "schema_version";
pub const KEY_ATTEMPT_TYPE: &str = "job_type";
pub const KEY_INPUT: &str = "input";
pub const KEY_PARENT_ATTEMPT: &str = "parent_job";

/// Encodes a Dreamer attempt payload in canonical MessagePack field order.
pub fn encode_dreamer_attempt_payload(payload: &DreamerAttemptPayload) -> Result<Vec<u8>> {
    validate_attempt_type(&payload.attempt_type)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_ATTEMPT_PAYLOAD_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ATTEMPT_TYPE),
            Value::from(payload.attempt_type.as_str()),
        ),
        (Value::from(KEY_INPUT), payload.input.clone()),
        (
            Value::from(KEY_PARENT_ATTEMPT),
            encode_optional_attempt_id(payload.parent_attempt),
        ),
    ]);
    encode_value(&value, "dreamer attempt payload MessagePack encode failed")
}

/// Decodes and validates a Dreamer attempt payload.
pub fn decode_dreamer_attempt_payload(bytes: &[u8]) -> Result<DreamerAttemptPayload> {
    let value = decode_value(bytes)?;
    decode_dreamer_attempt_payload_value(&value)
}

pub fn decode_dreamer_attempt_payload_value(value: &Value) -> Result<DreamerAttemptPayload> {
    let entries = expect_map(value, "dreamer attempt payload must be a MessagePack map")?;
    let mut schema_version = None;
    let mut attempt_type = None;
    let mut input = None;
    let mut parent_attempt = None;
    let mut seen = [false; DREAMER_ATTEMPT_PAYLOAD_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer attempt payload keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_ATTEMPT_PAYLOAD_KEYS).ok_or(
            invalid_dreamer_runner("dreamer attempt payload key is not pinned"),
        )?;
        if seen[index] {
            return Err(invalid_dreamer_runner(
                "duplicate dreamer attempt payload key",
            ));
        }
        seen[index] = true;

        match DREAMER_ATTEMPT_PAYLOAD_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer attempt payload schema_version must be an integer",
                )?);
            }
            KEY_ATTEMPT_TYPE => {
                let parsed = expect_string(value, "dreamer job_type must be a string")?;
                validate_attempt_type(&parsed)?;
                attempt_type = Some(parsed);
            }
            KEY_INPUT => input = Some(value.clone()),
            KEY_PARENT_ATTEMPT => parent_attempt = Some(decode_optional_attempt_id(value)?),
            _ => unreachable!("index resolved from DREAMER_ATTEMPT_PAYLOAD_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer attempt payload schema_version",
    ))?;
    if schema_version != DREAMER_ATTEMPT_PAYLOAD_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer attempt payload schema_version",
        ));
    }

    Ok(DreamerAttemptPayload {
        attempt_type: attempt_type.ok_or(invalid_dreamer_runner("missing dreamer job_type"))?,
        input: input.ok_or(invalid_dreamer_runner("missing dreamer attempt input"))?,
        parent_attempt: parent_attempt
            .ok_or(invalid_dreamer_runner("missing dreamer parent_job"))?,
    })
}

pub fn encode_value(value: &Value, reason: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(reason))?;
    Ok(out)
}

pub fn decode_value(bytes: &[u8]) -> Result<Value> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid_dreamer_runner("dreamer runner row is not valid MessagePack"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_dreamer_runner(
            "trailing bytes after dreamer runner row",
        ));
    }
    Ok(value)
}

pub fn encode_attempt_id(attempt_id: AttemptId) -> Value {
    Value::Binary(attempt_id.as_bytes().to_vec())
}

pub fn decode_attempt_id(value: &Value) -> Result<AttemptId> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_dreamer_runner("dreamer attempt id must be binary"));
    };
    AttemptId::from_bytes(bytes)
}

pub fn encode_optional_attempt_id(attempt_id: Option<AttemptId>) -> Value {
    attempt_id.map_or(Value::Nil, encode_attempt_id)
}

pub fn decode_optional_attempt_id(value: &Value) -> Result<Option<AttemptId>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    decode_attempt_id(value).map(Some)
}

pub fn expect_map<'a>(value: &'a Value, reason: &'static str) -> Result<&'a [(Value, Value)]> {
    let Value::Map(entries) = value else {
        return Err(invalid_dreamer_runner(reason));
    };
    Ok(entries)
}

pub fn expect_key<'a>(value: &'a Value, reason: &'static str) -> Result<&'a str> {
    value.as_str().ok_or(invalid_dreamer_runner(reason))
}

pub fn expect_string(value: &Value, reason: &'static str) -> Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(invalid_dreamer_runner(reason))
}

pub fn expect_u64(value: &Value, reason: &'static str) -> Result<u64> {
    value.as_u64().ok_or(invalid_dreamer_runner(reason))
}

pub fn pinned_key_index(key: &str, keys: &[&str]) -> Option<usize> {
    keys.iter().position(|known| *known == key)
}

pub fn validate_attempt_type(attempt_type: &str) -> Result<()> {
    if attempt_type.is_empty() {
        return Err(invalid_dreamer_runner("dreamer job_type must not be empty"));
    }
    Ok(())
}

pub const fn invalid_dreamer_runner(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(reason))
}
