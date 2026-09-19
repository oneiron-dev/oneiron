//! JSON codec shared by extraction and contradiction judgment.
use crate::entity_id::EntityId;
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

pub(super) fn entity_id_from_hex(hex: &str) -> Option<EntityId> {
    let hex = hex.trim();
    if hex.len() != 32 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut raw = [0_u8; 16];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        raw[index] = (high << 4) | low;
    }
    EntityId::from_bytes(raw).ok()
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
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
