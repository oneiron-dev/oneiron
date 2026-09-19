//! Unconditional credential removal before any context/export format writer.
use crate::batch::secret_scan::scan_file_content;
use serde_json::{Map, Value};

pub(super) fn credential_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(
        normalized.as_str(),
        "apikey"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "secret"
            | "secretkey"
            | "password"
            | "passwd"
            | "pwd"
            | "bearer"
            | "authorization"
            | "credentials"
            | "credential"
            | "privatekey"
            | "clientsecret"
            | "valuebytes"
            | "signingkey"
            | "signature"
            | "signatures"
            | "privatekeys"
            | "signingkeys"
    )
}

/// No option can bypass this transform. Recursion stops closed, not by returning the input.
pub(super) fn null_credentials(key: &str, value: &Value) -> Value {
    null_at_depth(key, value, 0)
}
fn null_at_depth(key: &str, value: &Value, depth: usize) -> Value {
    if depth >= 128 || credential_key(key) {
        return Value::Null;
    }
    match value {
        Value::String(text) if scan_file_content("", text.as_bytes()).is_some() => Value::Null,
        Value::Array(values) if encoded_credentials(values, depth) => Value::Null,
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| null_at_depth("", value, depth + 1))
                .collect(),
        ),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, value)| {
                    if scan_file_content("", key.as_bytes()).is_some() {
                        ("_redacted_key".to_owned(), Value::Null)
                    } else {
                        (key.clone(), null_at_depth(key, value, depth + 1))
                    }
                })
                .collect::<Map<_, _>>(),
        ),
        _ => value.clone(),
    }
}

// JSON byte arrays must be inspected as bytes, not as harmless decimal digits.
// Retain ordinary numeric arrays, but refuse encoded secrets and opaque nested
// containers just as the MessagePack serializer does.
fn encoded_credentials(values: &[Value], depth: usize) -> bool {
    if values.is_empty() {
        return false;
    }
    let Some(bytes): Option<Vec<u8>> = values
        .iter()
        .map(|value| value.as_u64().and_then(|v| u8::try_from(v).ok()))
        .collect()
    else {
        return false;
    };
    if scan_file_content("", &bytes).is_some() {
        return true;
    }
    if let Ok(value @ (Value::Object(_) | Value::Array(_))) = serde_json::from_slice(&bytes)
        && null_at_depth("", &value, depth + 1) != value
    {
        return true;
    }
    let mut cursor = std::io::Cursor::new(&bytes);
    matches!(
        rmpv::decode::read_value(&mut cursor),
        Ok(rmpv::Value::Map(_)
            | rmpv::Value::Array(_)
            | rmpv::Value::Binary(_)
            | rmpv::Value::Ext(_, _))
    ) && cursor.position() == bytes.len() as u64
}
