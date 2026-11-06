//! Core half of `serialize::credential_nulling`: its store-layer items live in `oneiron_store::serialize::credential_nulling` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::serialize::credential_nulling::*;

use crate::batch::secret_scan::{
    release_credential_field, release_joined_json, release_reads_json_text,
    release_reads_whole_json, scan_file_content, scan_text_content,
};
use serde_json::{Map, Value};
use std::collections::HashMap;

/// A field name whose value no export carries: this writer's own names, and
/// every name the release doors read as a credential (`DB_PASSWORD`,
/// `SERVICE_API_KEY`), whatever value it holds.
pub(super) fn credential_key(key: &str) -> bool {
    release_credential_field(key, false, None) || writer_credential_key(key)
}

/// No option can bypass this transform. Recursion stops closed, not by returning the input.
/// A structure that still reads as a secret once its parts are judged, read
/// whole as the release walks read it, is nulled whole.
pub(crate) fn null_credentials(key: &str, value: &Value) -> Value {
    null_whole(key, value, release_reads_whole_json)
}

/// [`null_credentials`] for the context writers. Their fields were hydrated
/// from bodies read in the encoding they were stored in, before the JSON
/// projection dropped each number's width, so the whole read takes the JSON's
/// text and no MessagePack form the body never had: a float read at a width
/// it was not stored at is other bytes.
pub(super) fn null_context_credentials(key: &str, value: &Value) -> Value {
    null_whole(key, value, release_reads_json_text)
}

fn null_whole(key: &str, value: &Value, reads_whole: fn(&Value) -> bool) -> Value {
    let nulled = null_at_depth(key, value, 0, false, &mut TextVerdicts::default());
    if matches!(nulled, Value::Array(_) | Value::Object(_)) && reads_whole(&nulled) {
        return Value::Null;
    }
    nulled
}

/// The whole-vault document pass. Its typed MessagePack trees were judged by the
/// serializer, which writes an `entity_reference` node only for an id slot. An id
/// must survive the archive, so its bytes are read for credentials rather than
/// nulled as an opaque container: an id hashed from its subject is random bytes,
/// and about 4 in 10,000 of those parse as a whole MessagePack container.
pub(super) fn null_document_credentials(value: &Value) -> Value {
    null_at_depth("", value, 0, true, &mut TextVerdicts::default())
}

/// One member of the whole-vault document as [`null_document_credentials`]
/// reads it in place: `key` is its field name (empty for an array item) and
/// `depth` its depth from the document root. A section's rows are objects, so
/// the section's own array readings never change one: a row read alone at its
/// depth is the row the whole pass leaves.
pub(super) fn null_document_member(key: &str, value: &Value, depth: usize) -> Value {
    null_at_depth(key, value, depth, true, &mut TextVerdicts::default())
}

/// One source-tree row as the export writer leaves it: `value` through
/// [`null_document_member`] at the depth `DocumentWriter::push_tree` holds
/// such a row at (key `""`, depth 2). A projection rebuilding an agent
/// bundle passes the rebuilt row through this before writing it.
pub(crate) fn null_document_tree_row(value: &Value) -> Value {
    null_document_member("", value, 2)
}

/// The release text verdict on each text one nulling pass reads, keyed by
/// the text itself, borrowed from the value the pass reads, so it holds no
/// copy of any text: a text read twice in one pass (a key every row repeats,
/// a value many items share) is scanned once (speed). It lives for one pass.
#[derive(Default)]
struct TextVerdicts<'a>(HashMap<&'a str, bool>);

impl<'a> TextVerdicts<'a> {
    /// Whether `text` reads as a secret by [`scan_file_content`]'s rules.
    fn reads_as_secret(&mut self, text: &'a str) -> bool {
        *self
            .0
            .entry(text)
            .or_insert_with(|| scan_text_content(text).is_some())
    }
}

fn null_at_depth<'a>(
    key: &str,
    value: &'a Value,
    depth: usize,
    document: bool,
    verdicts: &mut TextVerdicts<'a>,
) -> Value {
    if depth >= 128 || credential_key(key) {
        return Value::Null;
    }
    if document
        && let Value::Object(fields) = value
        && let Some(bytes) = entity_reference_bytes(fields)
    {
        // A credential-bearing id is nulled whole, as the typed serializer does.
        return if reference_carries_credential(&bytes, depth) {
            Value::Null
        } else {
            value.clone()
        };
    }
    match value {
        Value::String(text) if verdicts.reads_as_secret(text) => Value::Null,
        Value::Array(values) if encoded_credentials(values, depth) => Value::Null,
        Value::Array(values) if release_joined_json(values) => Value::Null,
        Value::Array(values) => {
            let kept: Vec<Value> = values
                .iter()
                .map(|value| null_at_depth("", value, depth + 1, document, verdicts))
                .collect();
            // Read again once items are nulled: the text left is what a second
            // pass reads joined, so the array is its own fixed point.
            if release_joined_json(&kept) {
                Value::Null
            } else {
                Value::Array(kept)
            }
        }
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, value)| {
                    if verdicts.reads_as_secret(key) {
                        ("_redacted_key".to_owned(), Value::Null)
                    } else {
                        (
                            key.clone(),
                            null_at_depth(key, value, depth + 1, document, verdicts),
                        )
                    }
                })
                .collect::<Map<_, _>>(),
        ),
        _ => value.clone(),
    }
}

/// An edge subject's reference holds two ids around its edge kind, and each is
/// read as an id too: a whole-value reading of the 33 bytes stops after one.
pub(super) fn reference_carries_credential(bytes: &[u8], depth: usize) -> bool {
    id_carries_credential(bytes, depth)
        || matches!(
            crate::write_envelope::claim_body::ClaimSubject::decode(bytes),
            Ok(crate::write_envelope::claim_body::ClaimSubject::Edge { source, target, .. })
                if id_carries_credential(source.as_bytes(), depth)
                    || id_carries_credential(target.as_bytes(), depth)
        )
}

/// Whether an id's bytes carry a credential under the release policy's own
/// detector: its text scan, and its field rule (`sensitive_key`, with nil and
/// placeholders exempt). Every reading is judged: the raw text, each value of a
/// JSON stream over that same lossy text or of a MessagePack stream (a reader
/// may stop after the first value or read on), and inside those each string,
/// binary, extension and numeric byte array read again as bytes, with every
/// map key. Container shape alone is no credential, so a credential-free id
/// survives the archive.
fn id_carries_credential(bytes: &[u8], depth: usize) -> bool {
    if depth >= 128 || scan_file_content("", bytes).is_some() {
        return true;
    }
    if serde_json::Deserializer::from_str(&String::from_utf8_lossy(bytes))
        .into_iter::<Json>()
        .map_while(Result::ok)
        .any(|value| json_names_credential(&value, depth + 1))
    {
        return true;
    }
    let mut cursor = std::io::Cursor::new(bytes);
    std::iter::from_fn(|| rmpv::decode::read_value(&mut cursor).ok())
        .any(|value| names_credential(&value, depth + 1))
}

fn json_names_credential(value: &Json, depth: usize) -> bool {
    if depth >= 128 {
        return true;
    }
    match value {
        Json::Text(text) => id_carries_credential(text.as_bytes(), depth),
        Json::List(items) => {
            let bytes = items.iter().map(|item| match item {
                Json::Byte(byte) => Some(*byte),
                _ => None,
            });
            bytes
                .collect::<Option<Vec<u8>>>()
                .is_some_and(|bytes| id_carries_credential(&bytes, depth))
                || items
                    .iter()
                    .any(|item| json_names_credential(item, depth + 1))
        }
        Json::Members(members) => members.iter().any(|(key, value)| {
            let text = match value {
                Json::Text(text) => Some(text.as_str()),
                _ => None,
            };
            release_credential_field(key, matches!(value, Json::Null), text)
                || id_carries_credential(key.as_bytes(), depth)
                || json_names_credential(value, depth + 1)
        }),
        Json::Null | Json::Byte(_) | Json::Other => false,
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
            key_name(key)
                .is_some_and(|name| release_credential_field(&name, value.is_nil(), value.as_str()))
                || names_credential(key, depth + 1)
                || names_credential(value, depth + 1)
        }),
        _ => false,
    }
}

fn json_carries_credential(bytes: &[u8], depth: usize) -> bool {
    // JSON opens an object or an array only with `{` or `[` past its
    // whitespace (a subset of ASCII whitespace): other bytes are not parsed.
    let first = bytes.iter().find(|byte| !byte.is_ascii_whitespace());
    matches!(first, Some(b'{' | b'['))
        && matches!(
            serde_json::from_slice::<Value>(bytes),
            Ok(value @ (Value::Object(_) | Value::Array(_)))
                if null_at_depth("", &value, depth + 1, false, &mut TextVerdicts::default())
                    != value
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
    // MessagePack reads a map, an array, binary or an extension value only
    // from its own leading markers: other bytes are not decoded.
    if !matches!(
        bytes.first(),
        Some(0x80..=0x9f | 0xc4..=0xc9 | 0xd4..=0xd8 | 0xdc..=0xdf)
    ) {
        return false;
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
