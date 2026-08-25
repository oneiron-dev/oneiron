use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::{EdgeKind, EntityId, Error, Result};

use super::replay::CODE_RUN_REPLAY_HASH_LEN;

pub(super) const CODE_RUN_OUTPUT_HANDLE_PREFIX: &str = "code-run-output:sha256:";
pub(super) const CODE_RUN_LAYOUT_HASH_DOMAIN: &[u8] = b"oneiron:code-run-replay-layout:v1";

pub(super) const CODE_RUN_REPLAY_MAX_LABEL_BYTES: usize = 512;
pub(super) const CODE_RUN_REPLAY_MAX_OUTPUT_PATH_BYTES: usize = 1024;

pub(super) fn request_map(entries: Vec<(&'static str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

pub(super) fn optional_value(value: Option<Value>) -> Value {
    value.unwrap_or(Value::Nil)
}

pub(super) fn optional_u64_value(value: Option<u64>) -> Value {
    value.map_or(Value::Nil, Value::from)
}

pub(super) fn optional_f32_value(value: Option<f32>) -> Value {
    value.map_or(Value::Nil, Value::F32)
}

pub(super) fn optional_entity_value(value: Option<EntityId>) -> Value {
    value.map_or(Value::Nil, entity_id_value)
}

pub(super) fn entity_id_value(id: EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

pub(super) fn pinned_map<'a, const N: usize>(
    value: &'a Value,
    keys: &[&str; N],
    context: &'static str,
) -> Result<[Option<&'a Value>; N]> {
    let entries = expect_map(value, context)?;
    let mut out = [None; N];
    for (key, value) in entries {
        let key = str_value(key)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_code_run_replay("map key is not pinned"));
        };
        if out[index].replace(value).is_some() {
            return Err(invalid_code_run_replay("duplicate map key"));
        }
    }
    Ok(out)
}

pub(super) fn expect_map<'a>(
    value: &'a Value,
    _context: &'static str,
) -> Result<&'a [(Value, Value)]> {
    let Value::Map(entries) = value else {
        return Err(invalid_code_run_replay("value must be a MessagePack map"));
    };
    Ok(entries)
}

pub(super) fn map_get<'a>(entries: &'a [(Value, Value)], needle: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(needle)).then_some(value))
        .ok_or(invalid_code_run_replay("missing dispatch outcome key"))
}

pub(super) fn required<'a>(value: Option<&'a Value>, message: &'static str) -> Result<&'a Value> {
    value.ok_or(invalid_code_run_replay(message))
}

pub(super) fn decode_array<T>(value: &Value, decode: fn(&Value) -> Result<T>) -> Result<Vec<T>> {
    let Value::Array(items) = value else {
        return Err(invalid_code_run_replay("value must be an array"));
    };
    items.iter().map(decode).collect()
}

pub(super) fn str_array(value: &Value) -> Result<Vec<String>> {
    let Value::Array(items) = value else {
        return Err(invalid_code_run_replay("value must be an array"));
    };
    items
        .iter()
        .map(|item| str_value(item).map(str::to_owned))
        .collect()
}

pub(super) fn decode_string_array(value: &Value) -> Result<Vec<String>> {
    let Value::Array(items) = value else {
        return Err(invalid_code_run_replay("fields must be an array"));
    };
    items
        .iter()
        .map(|item| str_value(item).map(ToOwned::to_owned))
        .collect()
}

pub(super) fn str_value(value: &Value) -> Result<&str> {
    value
        .as_str()
        .ok_or(invalid_code_run_replay("value must be a string"))
}

pub(super) fn bool_value(value: &Value) -> Result<bool> {
    match value {
        Value::Boolean(value) => Ok(*value),
        _ => Err(invalid_code_run_replay("value must be a boolean")),
    }
}

pub(super) fn u64_value(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .ok_or(invalid_code_run_replay("value must be an unsigned integer"))
}

pub(super) fn f32_value(value: &Value) -> Result<f32> {
    let parsed = match value {
        Value::F32(value) => *value,
        Value::F64(value) => *value as f32,
        _ => return Err(invalid_code_run_replay("value must be a float")),
    };
    if !parsed.is_finite() {
        return Err(invalid_code_run_replay("float must be finite"));
    }
    Ok(parsed)
}

pub(super) fn entity_value(value: &Value) -> Result<EntityId> {
    let bytes: [u8; 16] = fixed_binary(value, "entity id")?;
    EntityId::from_bytes(bytes).map_err(|_| invalid_code_run_replay("entity id is reserved"))
}

pub(super) fn edge_kind_value(value: &Value) -> Result<EdgeKind> {
    let raw = u8::try_from(u64_value(value)?)
        .map_err(|_| invalid_code_run_replay("edge kind byte overflow"))?;
    EdgeKind::try_from_u8(raw).ok_or(invalid_code_run_replay("unknown edge kind byte"))
}

pub(super) fn fixed_binary<const N: usize>(value: &Value, field: &'static str) -> Result<[u8; N]> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_code_run_replay(field));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_code_run_replay(field))
}

pub(super) fn validate_label(value: &str, field: &'static str) -> Result<()> {
    validate_text(value, CODE_RUN_REPLAY_MAX_LABEL_BYTES, field)
}

pub(super) fn validate_text(value: &str, max_bytes: usize, field: &'static str) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(invalid_code_run_replay(field));
    }
    Ok(())
}

pub(super) fn sha256_bytes(bytes: &[u8]) -> [u8; CODE_RUN_REPLAY_HASH_LEN] {
    Sha256::digest(bytes).into()
}

pub(super) fn code_run_layout_hash<I, S>(
    name: &str,
    schema_version: u64,
    fields: I,
) -> [u8; CODE_RUN_REPLAY_HASH_LEN]
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut hasher = Sha256::new();
    hasher.update(CODE_RUN_LAYOUT_HASH_DOMAIN);
    hasher.update([0]);
    hasher.update(name.as_bytes());
    hasher.update([0]);
    hasher.update(schema_version.to_be_bytes());
    for field in fields {
        hasher.update([0]);
        hasher.update(field.as_ref().as_bytes());
    }
    hasher.finalize().into()
}

pub(super) fn invalid_code_run_replay(message: &'static str) -> Error {
    Error::InvalidCodeArtifactBody(message)
}
