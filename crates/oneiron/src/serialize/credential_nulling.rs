//! Unconditional credential removal before any context/export format writer.
use crate::batch::secret_scan::{sanitize_messagepack_credentials, scan_file_content};
use rmpv::Value as Mp;
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
pub(crate) fn null_credentials(key: &str, value: &Value) -> Value {
    null_at_depth(key, value, 0, false)
}

/// The whole-vault document's second pass. Its typed tree writes an entity
/// reference where the body codec reads an id, and any id's bytes may also
/// decode as JSON or MessagePack, so a reference is nulled for a credential
/// in what they decode to, not for decoding (`reference_carries_credentials`).
/// It is nulled whole, never just its bytes, which no importer could decode.
pub(crate) fn null_document_credentials(value: &Value) -> Value {
    null_at_depth("", value, 0, true)
}

fn null_at_depth(key: &str, value: &Value, depth: usize, typed: bool) -> Value {
    if depth >= 128 || credential_key(key) {
        return Value::Null;
    }
    match value {
        Value::String(text) if scan_file_content("", text.as_bytes()).is_some() => Value::Null,
        Value::Array(values) if encoded_credentials(values, depth) => Value::Null,
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| null_at_depth("", value, depth + 1, typed))
                .collect(),
        ),
        Value::Object(fields) => {
            if typed && let Some(id) = entity_reference_bytes(fields) {
                return if reference_carries_credentials(&id, depth) {
                    Value::Null
                } else {
                    value.clone()
                };
            }
            Value::Object(
                fields
                    .iter()
                    .map(|(key, value)| {
                        if scan_file_content("", key.as_bytes()).is_some() {
                            ("_redacted_key".to_owned(), Value::Null)
                        } else {
                            (key.clone(), null_at_depth(key, value, depth + 1, typed))
                        }
                    })
                    .collect::<Map<_, _>>(),
            )
        }
        _ => value.clone(),
    }
}

/// `ExportValue::EntityReference` as serde writes it: `{"type":
/// "entity_reference", "value": [bytes]}`.
fn entity_reference_bytes(fields: &Map<String, Value>) -> Option<Vec<u8>> {
    if fields.len() != 2 || fields.get("type")?.as_str()? != "entity_reference" {
        return None;
    }
    fields
        .get("value")?
        .as_array()?
        .iter()
        .map(|value| value.as_u64().and_then(|v| u8::try_from(v).ok()))
        .collect()
}

/// Whether a reference's bytes carry a credential: in their text, or in what
/// they decode to as JSON or as one whole MessagePack value.
fn reference_carries_credentials(bytes: &[u8], depth: usize) -> bool {
    if depth >= 128 || scan_file_content("", bytes).is_some() {
        return true;
    }
    if let Ok(value @ (Value::Object(_) | Value::Array(_))) = serde_json::from_slice(bytes)
        && null_at_depth("", &value, depth + 1, false) != value
    {
        return true;
    }
    let mut cursor = std::io::Cursor::new(bytes);
    let Ok(value) = rmpv::decode::read_value(&mut cursor) else {
        return false;
    };
    cursor.position() == bytes.len() as u64 && messagepack_carries_credentials(&value, depth + 1)
}

/// What the MessagePack sanitizer finds, a field named as a credential, or a
/// credential in any byte string inside, read as a reference's bytes are.
fn messagepack_carries_credentials(value: &Mp, depth: usize) -> bool {
    if depth >= 128 || sanitize_messagepack_credentials(&mut value.clone(), true) {
        return true;
    }
    match value {
        Mp::Binary(bytes) | Mp::Ext(_, bytes) => reference_carries_credentials(bytes, depth + 1),
        Mp::Array(values) => {
            values
                .iter()
                .map(|value| value.as_u64().and_then(|v| u8::try_from(v).ok()))
                .collect::<Option<Vec<u8>>>()
                .is_some_and(|bytes| reference_carries_credentials(&bytes, depth + 1))
                || values
                    .iter()
                    .any(|value| messagepack_carries_credentials(value, depth + 1))
        }
        Mp::Map(entries) => entries.iter().any(|(key, value)| {
            key.as_str().is_some_and(credential_key)
                || messagepack_carries_credentials(key, depth + 1)
                || messagepack_carries_credentials(value, depth + 1)
        }),
        _ => false,
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
        && null_at_depth("", &value, depth + 1, false) != value
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
