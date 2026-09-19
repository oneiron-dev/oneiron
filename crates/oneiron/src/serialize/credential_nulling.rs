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
