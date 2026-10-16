//! The shape a result's head shows of its format, for its card and for the
//! way `query` reads it. It is sniffed from the first 64 KiB alone, so it
//! costs one ranged read whatever the body's size.

use super::query::split_fields;
use crate::code_run::CodeRunOutputKind;
use serde::Deserializer as _;
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde_json::{Value, json};

/// Top-level keys of a JSON object a shape lists at most.
const SHAPE_KEYS: usize = 64;

/// The shape of a body whose first bytes are `head`, all of it when
/// `whole`: JSON with its top type and first keys, JSON lines or a CSV/TSV
/// table with its columns, or plain text or binary.
pub(super) fn shape(head: &[u8], kind: CodeRunOutputKind, whole: bool) -> Value {
    if kind == CodeRunOutputKind::Binary {
        return json!({"format": "binary"});
    }
    let text = match std::str::from_utf8(head) {
        Ok(text) => text,
        Err(error) => std::str::from_utf8(&head[..error.valid_up_to()]).unwrap_or_default(),
    };
    let lines = first_lines(text, whole);
    if let [first, second] = lines.as_slice()
        && let (Ok(Value::Object(columns)), Ok(Value::Object(_))) = (
            serde_json::from_str::<Value>(first),
            serde_json::from_str::<Value>(second),
        )
    {
        return json!({"format": "jsonl", "columns": columns.keys().collect::<Vec<_>>()});
    }
    let document = text.trim_start();
    if document.starts_with('{') {
        let mut keys = Vec::new();
        let mut parser = serde_json::Deserializer::from_str(document);
        let complete = (&mut parser)
            .deserialize_map(TopKeys(&mut keys))
            .unwrap_or(false);
        return json!({"format": "json", "top": "object", "keys": keys, "partial": !complete});
    }
    if document.starts_with('[') {
        let complete = serde_json::from_str::<IgnoredAny>(document).is_ok();
        return json!({"format": "json", "top": "array", "partial": !complete});
    }
    if whole && let Ok(value) = serde_json::from_str::<Value>(document) {
        return json!({"format": "json", "top": top_word(&value), "partial": false});
    }
    for (format, delimiter) in [("tsv", b'\t'), ("csv", b',')] {
        if let [first, second] = lines.as_slice() {
            let columns = split_fields(first, delimiter);
            if columns.len() > 1 && split_fields(second, delimiter).len() == columns.len() {
                return json!({"format": format, "columns": columns});
            }
        }
    }
    json!({"format": "text"})
}

/// The first two lines of `text` that are not blank, each whole: a last
/// line with no newline after it counts only when `text` is the whole body.
fn first_lines(text: &str, whole: bool) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut segments = text.split('\n').peekable();
    while let Some(segment) = segments.next() {
        if segments.peek().is_none() && !whole {
            break;
        }
        let line = segment.strip_suffix('\r').unwrap_or(segment);
        if !line.trim().is_empty() {
            lines.push(line);
            if lines.len() == 2 {
                break;
            }
        }
    }
    lines
}

fn top_word(value: &Value) -> &'static str {
    match value {
        Value::Object(_) => "object",
        Value::Array(_) => "array",
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "bool",
        Value::Null => "null",
    }
}

/// Gathers a JSON object's first keys, skipping their values; whether it
/// read the object to its end.
struct TopKeys<'k>(&'k mut Vec<String>);

impl<'de> Visitor<'de> for TopKeys<'_> {
    type Value = bool;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if self.0.len() == SHAPE_KEYS {
                return Ok(false);
            }
            self.0.push(key);
            map.next_value::<IgnoredAny>()?;
        }
        Ok(true)
    }
}
