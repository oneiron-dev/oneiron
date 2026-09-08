//! Generic MessagePack map accessors, signature values, and semver compare.

use rmpv::Value;

use crate::gate::ceiling::PolicySignature;
use crate::gate::constants::{
    SIGNATURE_ALG_KEY, SIGNATURE_KEY_ID_KEY, SIGNATURE_SIG_KEY, SIGNATURE_SIGNATURE_KEY,
};

pub(super) enum MapValue<'a> {
    Missing,
    Present(&'a Value),
    Duplicate,
}

pub(super) fn single_map_value<'a>(entries: &'a [(Value, Value)], needle: &str) -> MapValue<'a> {
    let mut found = None;
    for (key, value) in entries {
        if key.as_str() == Some(needle) {
            if found.is_some() {
                return MapValue::Duplicate;
            }
            found = Some(value);
        }
    }
    found.map_or(MapValue::Missing, MapValue::Present)
}

pub(super) fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    match single_map_value(entries, key) {
        MapValue::Present(value) => Some(value),
        MapValue::Missing | MapValue::Duplicate => None,
    }
}

pub(super) fn optional_value(entries: &[(Value, Value)], key: &str) -> Option<Option<Value>> {
    match single_map_value(entries, key) {
        MapValue::Missing => Some(None),
        MapValue::Duplicate => None,
        MapValue::Present(value) => Some(Some(value.clone())),
    }
}

pub(super) fn required_string(entries: &[(Value, Value)], key: &str) -> Option<String> {
    required_value(entries, key)?.as_str().map(str::to_owned)
}

pub(super) fn optional_string(entries: &[(Value, Value)], key: &str) -> Option<Option<String>> {
    match single_map_value(entries, key) {
        MapValue::Missing => Some(None),
        MapValue::Duplicate => None,
        MapValue::Present(value) => {
            let value = value.as_str()?;
            if value.is_empty() {
                None
            } else {
                Some(Some(value.to_owned()))
            }
        }
    }
}

pub(super) fn required_nonempty_string(entries: &[(Value, Value)], key: &str) -> Option<String> {
    let value = required_string(entries, key)?;
    if value.is_empty() { None } else { Some(value) }
}

pub(super) fn optional_bool_default(
    entries: &[(Value, Value)],
    key: &str,
    default: bool,
) -> Option<bool> {
    match single_map_value(entries, key) {
        MapValue::Missing => Some(default),
        MapValue::Duplicate => None,
        MapValue::Present(Value::Boolean(value)) => Some(*value),
        MapValue::Present(_) => None,
    }
}

pub(super) fn optional_bool(entries: &[(Value, Value)], key: &str) -> Option<bool> {
    match single_map_value(entries, key) {
        MapValue::Missing => Some(false),
        MapValue::Duplicate => None,
        MapValue::Present(Value::Boolean(value)) => Some(*value),
        MapValue::Present(_) => None,
    }
}

pub(super) fn parse_signatures(value: &Value) -> Option<Vec<PolicySignature>> {
    let Value::Array(rows) = value else {
        return None;
    };
    rows.iter().map(parse_signature_value).collect()
}

pub(super) fn parse_signature_value(value: &Value) -> Option<PolicySignature> {
    match value {
        Value::String(sig) => Some(PolicySignature {
            alg: "unknown".to_owned(),
            key_id: None,
            sig: sig.as_str()?.to_owned(),
        }),
        Value::Map(entries) => {
            let alg = required_string(entries, SIGNATURE_ALG_KEY)?;
            let key_id = optional_string(entries, SIGNATURE_KEY_ID_KEY)?;
            let sig = match single_map_value(entries, SIGNATURE_SIG_KEY) {
                MapValue::Present(value) => value.as_str()?.to_owned(),
                MapValue::Missing => required_string(entries, SIGNATURE_SIGNATURE_KEY)?,
                MapValue::Duplicate => return None,
            };
            if alg.is_empty() || sig.is_empty() {
                return None;
            }
            Some(PolicySignature { alg, key_id, sig })
        }
        _ => None,
    }
}

pub(super) fn version_gt(left: &str, right: &str) -> Option<bool> {
    let left = parse_version(left)?;
    let right = parse_version(right)?;
    Some(left > right)
}

pub(super) fn parse_version(value: &str) -> Option<[u64; 3]> {
    let trimmed = value.strip_prefix('v').unwrap_or(value);
    let mut out = [0_u64; 3];
    let mut count = 0usize;
    for (index, part) in trimmed.split('.').enumerate() {
        if index >= out.len() || part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        out[index] = part.parse().ok()?;
        count += 1;
    }
    if count == 0 { None } else { Some(out) }
}
