//! Data projection between extraction/merge JSON and claim MessagePack values.
use rmpv::Value;

pub(super) fn rmpv_to_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Nil => serde_json::Value::Null,
        Value::Boolean(flag) => serde_json::Value::Bool(*flag),
        Value::Integer(number) => number
            .as_u64()
            .map(serde_json::Value::from)
            .or_else(|| number.as_i64().map(serde_json::Value::from))
            .unwrap_or(serde_json::Value::Null),
        Value::F32(number) => serde_json::Value::from(f64::from(*number)),
        Value::F64(number) => serde_json::Value::from(*number),
        Value::String(text) => text
            .as_str()
            .map_or(serde_json::Value::Null, serde_json::Value::from),
        Value::Array(items) => serde_json::Value::Array(items.iter().map(rmpv_to_json).collect()),
        Value::Map(entries) => serde_json::Value::Object(
            entries
                .iter()
                .filter_map(|(key, value)| {
                    key.as_str()
                        .map(|key| (key.to_owned(), rmpv_to_json(value)))
                })
                .collect(),
        ),
        _ => serde_json::Value::Null,
    }
}

pub(super) fn json_to_rmpv(value: &serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(flag) => Value::from(*flag),
        serde_json::Value::Number(number) => {
            if let Some(unsigned) = number.as_u64() {
                Value::from(unsigned)
            } else if let Some(signed) = number.as_i64() {
                Value::from(signed)
            } else {
                Value::from(number.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(text) => Value::from(text.as_str()),
        serde_json::Value::Array(items) => Value::Array(items.iter().map(json_to_rmpv).collect()),
        serde_json::Value::Object(entries) => Value::Map(
            entries
                .iter()
                .map(|(key, value)| (Value::from(key.as_str()), json_to_rmpv(value)))
                .collect(),
        ),
    }
}
