//! Unconditional credential removal before any context/export format writer.
use crate::batch::secret_scan::{
    sanitize_credentials, sanitize_messagepack_credentials, scan_file_content, sensitive_field_name,
};
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
/// serializer, which writes an `entity_reference` node only for an id slot. An id
/// must survive the archive, so its bytes are read for credentials rather than
/// nulled as an opaque container: an id hashed from its subject is random bytes,
/// and about 4 in 10,000 of those parse as a whole MessagePack container.
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
        // A credential-bearing id is nulled whole, as the typed serializer does.
        return if id_carries_credential(&bytes, depth) {
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

/// Whether an id's bytes carry a credential. Every reading of them is judged
/// by the release policy's own detector: the raw text, a JSON document, a
/// whole MessagePack value, and inside those each string, binary, extension
/// and numeric byte array read again as bytes. A field name counts when the
/// release policy or this serializer redacts it. Container shape alone is no
/// credential, so a credential-free id survives the archive.
fn id_carries_credential(bytes: &[u8], depth: usize) -> bool {
    if depth >= 128 || scan_file_content("", bytes).is_some() {
        return true;
    }
    if let Ok(value) = serde_json::from_slice::<Value>(bytes)
        && (sanitize_credentials(&mut value.clone(), true)
            || json_names_credential(&value, depth + 1))
    {
        return true;
    }
    let mut cursor = std::io::Cursor::new(bytes);
    rmpv::decode::read_value(&mut cursor).is_ok_and(|value| {
        cursor.position() == bytes.len() as u64
            && (sanitize_messagepack_credentials(&mut value.clone(), true)
                || names_credential(&value, depth + 1))
    })
}

fn json_names_credential(value: &Value, depth: usize) -> bool {
    if depth >= 128 {
        return true;
    }
    match value {
        Value::String(text) => id_carries_credential(text.as_bytes(), depth),
        Value::Array(values) => {
            json_bytes(values).is_some_and(|bytes| id_carries_credential(&bytes, depth))
                || values
                    .iter()
                    .any(|value| json_names_credential(value, depth + 1))
        }
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            credential_name(key)
                || id_carries_credential(key.as_bytes(), depth)
                || json_names_credential(value, depth + 1)
        }),
        _ => false,
    }
}

fn names_credential(value: &rmpv::Value, depth: usize) -> bool {
    if depth >= 128 {
        return true;
    }
    match value {
        rmpv::Value::String(text) => id_carries_credential(text.as_bytes(), depth),
        rmpv::Value::Binary(bytes) | rmpv::Value::Ext(_, bytes) => {
            id_carries_credential(bytes, depth)
        }
        rmpv::Value::Array(values) => {
            messagepack_bytes(values).is_some_and(|bytes| id_carries_credential(&bytes, depth))
                || values
                    .iter()
                    .any(|value| names_credential(value, depth + 1))
        }
        rmpv::Value::Map(entries) => entries.iter().any(|(key, value)| {
            key_name(key).is_some_and(|name| credential_name(&name))
                || names_credential(key, depth + 1)
                || names_credential(value, depth + 1)
        }),
        _ => false,
    }
}

/// One vocabulary: every name the release policy redacts, and the names this
/// serializer nulls anywhere else in the document.
fn credential_name(name: &str) -> bool {
    sensitive_field_name(name) || credential_key(name)
}

/// A map key read as a field name, whether text, binary, extension or bytes.
fn key_name(key: &rmpv::Value) -> Option<String> {
    let bytes = match key {
        rmpv::Value::String(text) => text.as_bytes().to_vec(),
        rmpv::Value::Binary(bytes) | rmpv::Value::Ext(_, bytes) => bytes.clone(),
        rmpv::Value::Array(values) => messagepack_bytes(values)?,
        _ => return None,
    };
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn messagepack_bytes(values: &[rmpv::Value]) -> Option<Vec<u8>> {
    values
        .iter()
        .map(|value| value.as_u64().and_then(|v| u8::try_from(v).ok()))
        .collect()
}

fn json_carries_credential(bytes: &[u8], depth: usize) -> bool {
    matches!(
        serde_json::from_slice::<Value>(bytes),
        Ok(value @ (Value::Object(_) | Value::Array(_)))
            if null_at_depth("", &value, depth + 1, false) != value
    )
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
    if scan_file_content("", &bytes).is_some() || json_carries_credential(&bytes, depth) {
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
