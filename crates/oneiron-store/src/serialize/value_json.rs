//! The opaque MessagePack value a record carries, to and from the JSON public
//! APIs read and write.

use oneiron_base::error::{Error, Result};
use oneiron_contracts::msgpack;
use rmpv::Value;
use serde_json::{Number, Value as JsonValue};

/// The MessagePack value of a JSON value: null, booleans, text, arrays and
/// objects (in their key order) as themselves, an integer as an integer and
/// any other number as a 64-bit float. It refuses nothing; a door that keeps
/// the value calls [`msgpack_value_from_json`].
#[must_use]
pub fn json_to_msgpack_value(value: &JsonValue) -> Value {
    match value {
        JsonValue::Null => Value::Nil,
        JsonValue::Bool(flag) => Value::Boolean(*flag),
        JsonValue::Number(number) => msgpack_number(number),
        JsonValue::String(text) => Value::from(text.as_str()),
        JsonValue::Array(items) => Value::Array(items.iter().map(json_to_msgpack_value).collect()),
        JsonValue::Object(entries) => Value::Map(
            entries
                .iter()
                .map(|(key, item)| (Value::from(key.as_str()), json_to_msgpack_value(item)))
                .collect(),
        ),
    }
}

/// An integer first, as unsigned or signed (both give the one
/// `rmpv::Integer` of its value); else the 64-bit float JSON holds.
fn msgpack_number(number: &Number) -> Value {
    match (number.as_u64(), number.as_i64(), number.as_f64()) {
        (Some(unsigned), _, _) => Value::from(unsigned),
        (None, Some(signed), _) => Value::from(signed),
        (None, None, Some(float)) => Value::F64(float),
        // serde_json gives every number an `f64` unless its
        // `arbitrary_precision` feature is on, and no crate turns it on.
        (None, None, None) => Value::Nil,
    }
}

/// Converts JSON accepted by public APIs into the opaque MessagePack value a
/// record carries: [`json_to_msgpack_value`], refused when the one reader
/// cannot read its bytes back (a value nested deeper than `rmpv` reads), so
/// no record holds a value it cannot decode.
pub fn msgpack_value_from_json(value: &JsonValue) -> Result<Value> {
    msgpack::decode(&msgpack::encode(&json_to_msgpack_value(value)))
        .map_err(|_| Error::InvalidClaimBody("value is not valid MessagePack"))
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
pub fn msgpack_value_projection(value: &Value) -> Value {
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

/// The JSON of `value` when JSON holds it exactly, else none: binary, an
/// extension, a non-finite float, a string that is no UTF-8, and a map key
/// that is not text or appears twice have no JSON form. A 32-bit float reads
/// as the 64-bit float of its value, and every number loses its width.
#[must_use]
pub fn msgpack_value_to_exact_json(value: &Value) -> Option<JsonValue> {
    Some(match value {
        Value::Nil => JsonValue::Null,
        Value::Boolean(flag) => JsonValue::Bool(*flag),
        Value::Integer(number) => match number.as_u64() {
            Some(unsigned) => unsigned.into(),
            None => number.as_i64()?.into(),
        },
        Value::F32(number) => Number::from_f64(f64::from(*number))?.into(),
        Value::F64(number) => Number::from_f64(*number)?.into(),
        Value::String(text) => text.as_str()?.into(),
        Value::Array(items) => JsonValue::Array(
            items
                .iter()
                .map(msgpack_value_to_exact_json)
                .collect::<Option<Vec<_>>>()?,
        ),
        Value::Map(entries) => {
            let mut object = serde_json::Map::with_capacity(entries.len());
            for (key, item) in entries {
                if object
                    .insert(key.as_str()?.to_owned(), msgpack_value_to_exact_json(item)?)
                    .is_some()
                {
                    return None;
                }
            }
            JsonValue::Object(object)
        }
        Value::Binary(_) | Value::Ext(..) => return None,
    })
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
