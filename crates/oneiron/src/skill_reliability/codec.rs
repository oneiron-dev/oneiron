//! The msgpack map accessors and value encode/decode this module’s rows are read through.

use rmpv::Value;

use crate::error::{ArtifactError, Error, Result};

pub(super) const ENTITY_ID_LEN: usize = 16;

pub(super) const KEY_SCHEMA_VERSION: &str = "schema_version";

pub(super) const KEY_WIN: &str = "win";

pub(super) const KEY_AT: &str = "at";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub(super) const fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(reason))
}

pub(super) fn map_entry<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .map(|(_, v)| v)
}

pub(super) fn map_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    map_entry(value, key)?.as_str()
}

pub(super) fn map_u64(value: &Value, key: &str) -> Option<u64> {
    map_entry(value, key)?.as_u64()
}

pub(super) fn map_f32(value: &Value, key: &str) -> Option<f32> {
    match map_entry(value, key)? {
        Value::F32(v) => Some(*v),
        Value::F64(v) => Some(*v as f32),
        _ => None,
    }
}

pub(super) fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, value)
        .map_err(|_| invalid("skill reliability MessagePack encode failed"))?;
    Ok(encoded)
}

pub(super) fn decode_value(raw: &[u8]) -> Result<Value> {
    rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| invalid("skill reliability MessagePack decode failed"))
}
