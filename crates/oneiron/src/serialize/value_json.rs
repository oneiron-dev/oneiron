//! The opaque MessagePack value a record carries, to and from the JSON public
//! APIs read and write.

use crate::error::{Error, Result};
use rmpv::Value;
use serde_json::Value as JsonValue;
use std::io::Cursor;

/// Converts JSON accepted by public APIs into the opaque MessagePack value a
/// record carries.
pub fn msgpack_value_from_json(value: &JsonValue) -> Result<Value> {
    let encoded = rmp_serde::to_vec_named(value)
        .map_err(|_| Error::InvalidClaimBody("value must be msgpack-encodable JSON"))?;
    let mut cursor = Cursor::new(encoded.as_slice());
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidClaimBody("value is not valid MessagePack"))?;
    if cursor.position() != encoded.len() as u64 {
        return Err(Error::InvalidClaimBody("trailing bytes after value"));
    }
    Ok(value)
}

/// Converts an opaque MessagePack value back to JSON for typed API
/// envelopes. MessagePack binary/ext values are redacted because they are not
/// JSON-shaped public API values.
#[must_use]
pub fn msgpack_value_to_json(value: &Value) -> JsonValue {
    projected_json(msgpack_value_projection(value))
}

/// What [`msgpack_value_to_json`] keeps of a value, still as MessagePack:
/// binary, extension and non-finite floats as nil, a string that is no UTF-8
/// as the `invalid_utf8_string` marker, and a map's text keys once each (the
/// last value at the first key's place), as a JSON object keeps them. Each
/// number keeps the width that JSON drops, so a reader can read this value
/// exactly as the JSON it becomes.
pub(crate) fn msgpack_value_projection(value: &Value) -> Value {
    match value {
        Value::F32(number) if !number.is_finite() => Value::Nil,
        Value::F64(number) if !number.is_finite() => Value::Nil,
        Value::String(text) if text.as_str().is_none() => Value::Map(vec![(
            Value::from("redacted"),
            Value::from("invalid_utf8_string"),
        )]),
        Value::Binary(_) | Value::Ext(_, _) => Value::Nil,
        Value::Array(values) => Value::Array(values.iter().map(msgpack_value_projection).collect()),
        Value::Map(entries) => {
            let mut kept: Vec<(Value, Value)> = Vec::with_capacity(entries.len());
            let mut at: std::collections::HashMap<&str, usize> =
                std::collections::HashMap::with_capacity(entries.len());
            for (key, value) in entries {
                let Some(key) = key.as_str() else {
                    continue;
                };
                let value = msgpack_value_projection(value);
                match at.entry(key) {
                    std::collections::hash_map::Entry::Occupied(slot) => {
                        kept[*slot.get()].1 = value;
                    }
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(kept.len());
                        kept.push((Value::from(key), value));
                    }
                }
            }
            Value::Map(kept)
        }
        other => other.clone(),
    }
}

/// A [`msgpack_value_projection`] as JSON, which loses only number widths.
fn projected_json(value: Value) -> JsonValue {
    match value {
        Value::Boolean(value) => JsonValue::Bool(value),
        Value::Integer(value) => match (value.as_i64(), value.as_u64()) {
            (Some(signed), _) => JsonValue::from(signed),
            (None, Some(unsigned)) => JsonValue::from(unsigned),
            (None, None) => JsonValue::Null,
        },
        Value::F32(value) => serde_json::json!(value),
        Value::F64(value) => serde_json::json!(value),
        Value::String(value) => value.into_str().map_or(JsonValue::Null, JsonValue::String),
        Value::Array(values) => JsonValue::Array(values.into_iter().map(projected_json).collect()),
        Value::Map(entries) => JsonValue::Object(
            entries
                .into_iter()
                .filter_map(|(key, value)| match key {
                    Value::String(key) => Some((key.into_str()?, projected_json(value))),
                    _ => None,
                })
                .collect(),
        ),
        Value::Nil | Value::Binary(_) | Value::Ext(_, _) => JsonValue::Null,
    }
}
