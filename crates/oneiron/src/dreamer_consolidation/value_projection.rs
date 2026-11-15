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
