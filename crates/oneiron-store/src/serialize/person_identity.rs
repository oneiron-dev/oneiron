//! Pure PERSON baseline validation and JSON-compatible MessagePack decoding.

use crate::serialize::value_json::msgpack_value_to_json;
use crate::write_envelope::person_identity::{body_fields, invalid_companion};
use oneiron_base::error::Result;
use rmpv::Value;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::BTreeSet;

pub const BASELINE_KEY: &str = "persona_definition";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineWire {
    pub schema_version: u8,
    pub baseline: JsonValue,
}

pub fn object(value: &JsonValue) -> Result<()> {
    if !value.is_object() {
        return Err(invalid_companion("persona payload must be a JSON object"));
    }
    Ok(())
}

pub fn validate_json(value: &Value, depth: usize) -> Result<()> {
    if depth > 128 {
        return Err(invalid_companion("persona JSON is too deeply nested"));
    }
    match value {
        Value::Binary(_) | Value::Ext(_, _) => {
            return Err(invalid_companion("persona JSON cannot carry binary values"));
        }
        Value::F32(number) if !number.is_finite() => {
            return Err(invalid_companion("persona JSON number is not finite"));
        }
        Value::F64(number) if !number.is_finite() => {
            return Err(invalid_companion("persona JSON number is not finite"));
        }
        Value::String(text) if text.as_str().is_none() => {
            return Err(invalid_companion("persona JSON string is not UTF-8"));
        }
        Value::Map(entries) => {
            let mut keys = BTreeSet::new();
            for (key, value) in entries {
                let key = key
                    .as_str()
                    .ok_or_else(|| invalid_companion("persona JSON key is not text"))?;
                if !keys.insert(key) {
                    return Err(invalid_companion("duplicate persona JSON key"));
                }
                validate_json(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_json(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn from_value<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T> {
    // The generic MessagePack-to-JSON projection redacts binary values.
    // Compilation must instead reject them: redacting to null would turn data
    // into a deletion.
    validate_json(value, 0)?;
    serde_json::from_value(msgpack_value_to_json(value))
        .map_err(|_| invalid_companion("invalid persona value"))
}

pub fn field<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
        .ok_or_else(|| invalid_companion("persona record field is missing"))
}

/// The PERSON identity baseline accepted by both onboarding and scoped replay.
/// Decodes the entire body (including duplicate/trailing-key checks), not just
/// the presence of a `persona_definition` field.
pub fn validated_persona_baseline(data: &[u8]) -> Result<JsonValue> {
    let baseline: BaselineWire = from_value(field(&body_fields(data)?, BASELINE_KEY)?)?;
    if baseline.schema_version != 1 {
        return Err(invalid_companion("unsupported persona baseline version"));
    }
    object(&baseline.baseline)?;
    Ok(baseline.baseline)
}
