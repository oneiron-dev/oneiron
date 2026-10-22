//! JSON and MessagePack wire helpers: conversion, body decoding, provenance and requested approval.
//! `json_to_rmpv` and `encode_rmpv` are its call surface.
//! `memory::support` re-exports these at their old reach.

use super::*;

pub(in crate::memory) fn json_to_rmpv(value: &serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Value::from(u)
            } else if let Some(i) = n.as_i64() {
                Value::from(i)
            } else {
                Value::from(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => Value::from(s.as_str()),
        serde_json::Value::Array(items) => Value::Array(items.iter().map(json_to_rmpv).collect()),
        serde_json::Value::Object(entries) => Value::Map(
            entries
                .iter()
                .map(|(k, v)| (Value::from(k.as_str()), json_to_rmpv(v)))
                .collect(),
        ),
    }
}

pub(in crate::memory) fn encode_rmpv(value: &Value) -> MemoryResult<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value)
        .map_err(|_| MemoryError::bad_request("body is not MessagePack-encodable"))?;
    Ok(out)
}

pub(in crate::memory) fn decode_body_json(bytes: &[u8]) -> Option<serde_json::Value> {
    if bytes.is_empty() {
        return None;
    }
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    if !cursor.is_empty() {
        return None;
    }
    Some(crate::batch::export::served_stored_messagepack_json(
        bytes, value,
    ))
}

pub(crate) fn facade_provenance(verb: &str) -> Value {
    Value::Map(vec![
        (Value::from("surface"), Value::from("facade")),
        (Value::from("verb"), Value::from(verb)),
    ])
}

pub(in crate::memory) fn requested_approval(
    source: ClaimSource,
    scope: Option<&serde_json::Value>,
) -> ClaimApprovalStatus {
    let auto_source = matches!(source, ClaimSource::UserStated | ClaimSource::Observed);
    let has_sensitivity_key = scope
        .and_then(serde_json::Value::as_object)
        .is_some_and(|map| map.contains_key(SCOPE_SENSITIVITY_KEY));
    if auto_source && !has_sensitivity_key {
        ClaimApprovalStatus::Auto
    } else {
        ClaimApprovalStatus::Proposed
    }
}
