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
pub(crate) fn null_credentials(key: &str, value: &Value) -> Value {
    null_at_depth(key, value, 0, false)
}

/// The whole-vault document pass. Its typed MessagePack trees were judged by the
/// serializer, which writes an `entity_reference` node only for a validated id.
/// Those bytes keep the secret scan but not the opaque-container rule: an id
/// hashed from its subject is random bytes, about 4 in 10,000 parse as a whole
/// MessagePack container, and nulling one left an archive the importer refused.
pub(super) fn null_document_credentials(value: &Value) -> Value {
    null_at_depth("", value, 0, true)
}

fn null_at_depth(key: &str, value: &Value, depth: usize, document: bool) -> Value {
    if depth >= 128 || credential_key(key) {
        return Value::Null;
    }
    if document
        && let Value::Object(fields) = value
        && let Some(bytes) = entity_reference_bytes(fields)
    {
        // A secret-shaped id is nulled whole, as the typed serializer does.
        return if scan_file_content("", &bytes).is_some() {
            Value::Null
        } else {
            value.clone()
        };
    }
    match value {
        Value::String(text) if scan_file_content("", text.as_bytes()).is_some() => Value::Null,
        Value::Array(values) if encoded_credentials(values, depth) => Value::Null,
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| null_at_depth("", value, depth + 1, document))
                .collect(),
        ),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, value)| {
                    if scan_file_content("", key.as_bytes()).is_some() {
                        ("_redacted_key".to_owned(), Value::Null)
                    } else {
                        (key.clone(), null_at_depth(key, value, depth + 1, document))
                    }
                })
                .collect::<Map<_, _>>(),
        ),
        _ => value.clone(),
    }
}

/// The typed tree's `{"type": "entity_reference", "value": [byte, ...]}` node.
fn entity_reference_bytes(fields: &Map<String, Value>) -> Option<Vec<u8>> {
    if fields.len() != 2 || fields.get("type")?.as_str()? != "entity_reference" {
        return None;
    }
    json_bytes(fields.get("value")?.as_array()?)
}

fn json_bytes(values: &[Value]) -> Option<Vec<u8>> {
    values
        .iter()
        .map(|value| value.as_u64().and_then(|v| u8::try_from(v).ok()))
        .collect()
}

// JSON byte arrays must be inspected as bytes, not as harmless decimal digits.
// Retain ordinary numeric arrays, but refuse encoded secrets and opaque nested
// containers just as the MessagePack serializer does.
fn encoded_credentials(values: &[Value], depth: usize) -> bool {
    if values.is_empty() {
        return false;
    }
    let Some(bytes) = json_bytes(values) else {
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
