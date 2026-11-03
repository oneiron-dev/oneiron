//! The shape a result's head shows of its format, for its card and for the
//! way `query` reads it. It is sniffed from the first 64 KiB, extended to
//! 1 MiB when that head is not the whole body and shows fewer than two
//! whole nonblank lines or fewer than two logical table rows for some
//! delimiter, so the card and `query` cannot disagree; the sniff stays
//! uncharged.

use super::query::{CsvOpen, split_fields_open};
use super::{READ_PIECE_BYTES, ResultBody};
use crate::Result;
use crate::code_run::CodeRunOutputKind;
use serde::Deserializer as _;
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde_json::{Value, json};

/// Top-level keys of a JSON object a shape lists at most.
const SHAPE_KEYS: usize = 64;

/// The shape of `body` from its initial `head`, the bytes of
/// `body.read(0, SHAPE_HEAD_BYTES)`, extended forward to `READ_PIECE_BYTES`
/// in total when that head is not the whole body and shows fewer than two
/// whole nonblank lines or fewer than two logical table rows for some
/// delimiter (FIX 1187). The card and `query` share it, so they
/// cannot disagree. Binary answers at once with no extension; a whole body
/// or a head that already shows two lines reads nothing more. The sniff
/// stays uncharged, and past the ceiling the existing [`shape`] fallback
/// answers.
pub(super) fn shape_of(body: &dyn ResultBody, mut head: Vec<u8>) -> Result<Value> {
    let kind = body.kind();
    let len = body.len();
    if kind == CodeRunOutputKind::Binary {
        return Ok(shape(&head, kind, head.len() as u64 == len));
    }
    if head.len() as u64 == len {
        return Ok(shape(&head, kind, true));
    }
    let text = match std::str::from_utf8(&head) {
        Ok(text) => text,
        Err(error) => std::str::from_utf8(&head[..error.valid_up_to()]).unwrap_or_default(),
    };
    if first_lines(text, false).len() >= 2
        && [b'\t', b',']
            .iter()
            .all(|&d| first_table_rows(text, false, d).len() >= 2)
    {
        return Ok(shape(&head, kind, false));
    }
    let want = READ_PIECE_BYTES.saturating_sub(head.len());
    if want > 0 {
        let extra = body.read(head.len() as u64, want)?;
        head.extend_from_slice(&extra);
    }
    let whole = head.len() as u64 == len;
    Ok(shape(&head, kind, whole))
}

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
        let rows = first_table_rows(text, whole, delimiter);
        if let [columns, second] = rows.as_slice()
            && columns.len() > 1
            && second.len() == columns.len()
        {
            return json!({"format": format, "columns": columns});
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

/// The first two logical rows of a delimited table: quoted newlines join
/// their physical lines, and only a row's final CR is discarded. A partial
/// physical line at a non-whole head never counts as a row.
fn first_table_rows(text: &str, whole: bool, delimiter: u8) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut logical = String::new();
    let mut open = CsvOpen::new();
    let mut segments = text.split('\n').peekable();
    while let Some(segment) = segments.next() {
        if segments.peek().is_none() && !whole {
            break;
        }
        if logical.is_empty() && segment.trim().is_empty() {
            continue;
        }
        logical.push_str(segment);
        open.feed(segment.as_bytes(), delimiter);
        open.end_physical();
        if open.is_open() {
            logical.push('\n');
            open.feed_byte(b'\n', delimiter);
            continue;
        }
        if logical.ends_with('\r') {
            logical.pop();
        }
        rows.push(split_fields_open(&logical, delimiter).0);
        if rows.len() == 2 {
            break;
        }
        logical.clear();
        open = CsvOpen::new();
    }
    rows
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

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<bool, A::Error> {
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
