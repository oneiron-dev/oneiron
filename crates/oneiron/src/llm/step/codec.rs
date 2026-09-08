//! Pinned-key MessagePack codec helpers shared by every step-layer decoder.

use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use rmpv::Value;

// ---------------------------------------------------------------------------
// Codec helpers (the pinned_key_index idiom, local to the step layer)
// ---------------------------------------------------------------------------
pub(super) const fn invalid_step(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

pub(super) const fn invalid_trap(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

pub(super) fn pinned_key_index(key: &str, keys: &[&str]) -> Option<usize> {
    keys.iter().position(|pinned| *pinned == key)
}

pub(super) fn expect_map<'v>(
    value: &'v Value,
    context: &'static str,
) -> Result<&'v Vec<(Value, Value)>> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(invalid_step(context)),
    }
}

pub(super) fn expect_key<'v>(key: &'v Value, context: &'static str) -> Result<&'v str> {
    key.as_str().ok_or(invalid_step(context))
}

pub(super) fn expect_u64(value: &Value, context: &'static str) -> Result<u64> {
    value.as_u64().ok_or(invalid_step(context))
}

pub(super) fn expect_string(value: &Value, context: &'static str) -> Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(invalid_step(context))
}

pub(super) fn decode_attempt_id_value(value: &Value) -> Result<AttemptId> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_step("dreamer step job_id must be binary"));
    };
    AttemptId::from_bytes(bytes)
}

pub(super) fn decode_entity_id_value(value: &Value) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_step("dreamer step response_ref must be binary"));
    };
    let raw: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_step("dreamer step response_ref must be 16 bytes"))?;
    EntityId::from_bytes(raw)
}

pub(super) fn decode_hash_hex(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_step("dreamer step step_hash must be 64 hex chars"));
    }
    let mut out = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

const fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(invalid_step("dreamer step step_hash must be hex")),
    }
}
