//! JSON renderings of MessagePack claim values for command output.

use rmpv::Value as MsgpackValue;
use serde_json::{Value as JsonValue, json};

const MAX_MSGPACK_JSON_DEPTH: usize = 32;

pub(crate) fn msgpack_value_json(value: &MsgpackValue) -> JsonValue {
    msgpack_value_json_with_depth(value, MAX_MSGPACK_JSON_DEPTH)
}

pub(super) fn msgpack_value_json_with_depth(
    value: &MsgpackValue,
    remaining_depth: usize,
) -> JsonValue {
    match value {
        MsgpackValue::Nil => JsonValue::Null,
        MsgpackValue::Boolean(value) => json!(value),
        MsgpackValue::Integer(value) => value
            .as_i64()
            .map_or_else(|| json!(value.as_u64()), |value| json!(value)),
        MsgpackValue::F32(value) => json!(value),
        MsgpackValue::F64(value) => json!(value),
        MsgpackValue::String(value) => value.as_str().map_or_else(
            || json!({ "string": value.to_string() }),
            |value| json!(value),
        ),
        MsgpackValue::Binary(value) => json!({ "binary_hex": hex_bytes(value) }),
        MsgpackValue::Array(_) | MsgpackValue::Map(_) if remaining_depth == 0 => {
            json!({ "truncated": "max_depth" })
        }
        MsgpackValue::Array(values) => JsonValue::Array(
            values
                .iter()
                .map(|value| msgpack_value_json_with_depth(value, remaining_depth - 1))
                .collect(),
        ),
        MsgpackValue::Map(values) => {
            let mut map = serde_json::Map::new();
            for (key, value) in values {
                insert_json_map_value(
                    &mut map,
                    msgpack_map_key(key, remaining_depth - 1),
                    msgpack_value_json_with_depth(value, remaining_depth - 1),
                );
            }
            JsonValue::Object(map)
        }
        MsgpackValue::Ext(tag, value) => json!({
            "ext_type": tag,
            "data_hex": hex_bytes(value),
        }),
    }
}

fn msgpack_map_key(value: &MsgpackValue, remaining_depth: usize) -> String {
    match value {
        MsgpackValue::String(value) => value
            .as_str()
            .map_or_else(|| value.to_string(), std::borrow::ToOwned::to_owned),
        _ => serde_json::to_string(&msgpack_value_json_with_depth(value, remaining_depth))
            .unwrap_or_else(|_| format!("{value:?}")),
    }
}

fn insert_json_map_value(
    map: &mut serde_json::Map<String, JsonValue>,
    key: String,
    value: JsonValue,
) {
    if !map.contains_key(&key) {
        map.insert(key, value);
        return;
    }
    for index in 2.. {
        let candidate = format!("{key}#{index}");
        if !map.contains_key(&candidate) {
            map.insert(candidate, value);
            return;
        }
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
