//! The msgpack map accessors and value encode/decode this module’s rows are read through.

use rmpv::Value;

use crate::error::{ArtifactError, Error, Result};
use oneiron_contracts::msgpack;

pub(super) const KEY_SCHEMA_VERSION: &str = "schema_version";

pub(super) const KEY_WIN: &str = "win";

pub(super) const KEY_AT: &str = "at";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub(super) const fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(reason))
}

const DUPLICATE_KEY: &str = "skill reliability map repeats a key";

/// The entry under `key`, `None` when `value` is not a map or lacks `key`. A key stored twice is refused.
pub(super) fn map_entry<'a>(value: &'a Value, key: &str) -> Result<Option<&'a Value>> {
    let Value::Map(entries) = value else {
        return Ok(None);
    };
    msgpack::Entries::new(entries)
        .get(key)
        .map_err(|_| invalid(DUPLICATE_KEY))
}

/// The text under `key`, `None` when it is absent or not text. A key stored twice is refused.
pub(super) fn map_str<'a>(value: &'a Value, key: &str) -> Result<Option<&'a str>> {
    Ok(map_entry(value, key)?.and_then(Value::as_str))
}

/// The unsigned integer under `key`, `None` when it is absent or not one. A key stored twice is refused.
pub(super) fn map_u64(value: &Value, key: &str) -> Result<Option<u64>> {
    Ok(map_entry(value, key)?.and_then(Value::as_u64))
}

/// The float under `key`, `None` when it is absent or not one. A key stored twice is refused.
pub(super) fn map_f32(value: &Value, key: &str) -> Result<Option<f32>> {
    Ok(match map_entry(value, key)? {
        Value::F32(v) => Some(*v),
        Value::F64(v) => Some(*v as f32),
        _ => None,
    })
}

pub(super) fn encode_value(value: &Value) -> Result<Vec<u8>> {
    Ok(msgpack::encode(value))
}

pub(super) fn decode_value(raw: &[u8]) -> Result<Value> {
    msgpack::decode(raw).map_err(|_| invalid("skill reliability MessagePack decode failed"))
}
