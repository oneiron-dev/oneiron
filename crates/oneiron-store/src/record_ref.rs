//! Typed record references and bounded record display labels.

use serde::{Deserialize, Serialize};

/// The most characters a [`RecordRef`] label carries.
pub const RECORD_REF_LABEL_MAX_CHARS: usize = 80;

/// The body fields a label is read from; the first one holding text wins.
pub const LABEL_FIELDS: [&str; 6] = [
    "title",
    "name",
    "label",
    "display_name",
    "predicate",
    "subject",
];
/// The body fields a CLAIM's label is read from: its value.
pub const CLAIM_LABEL_FIELDS: [&str; 1] = ["val"];
/// The body fields a PERSON's label is read from: the name it shows.
pub const PERSON_LABEL_FIELDS: [&str; 2] = ["display_name", "name"];

/// A short ref without the `@<revision>` a pinned read qualifies it with.
pub fn bare_short_ref(short: &str) -> String {
    short
        .rsplit_once('@')
        .map_or(short, |(bare, _)| bare)
        .to_owned()
}

/// The first of `fields` in `body` that holds text. A claim's non-text
/// value (`value`, or a CLAIM body's `val`) is shown as its compact JSON.
pub fn first_text(body: &serde_json::Value, fields: &[&str]) -> Option<String> {
    let object = body.as_object()?;
    fields.iter().find_map(|field| match object.get(*field)? {
        serde_json::Value::String(text) if !text.trim().is_empty() => Some(text.clone()),
        serde_json::Value::Null | serde_json::Value::String(_) => None,
        other if matches!(*field, "value" | "val") => Some(other.to_string()),
        _ => None,
    })
}

/// The label a record with no title of its own shows: its kind and short id
/// (the first 8 hex of its id when it has none).
pub fn fallback_label(kind: &str, short_id: Option<&str>, id_hex: &str) -> String {
    let name = short_id.map_or_else(|| id_hex.chars().take(8).collect(), str::to_owned);
    bounded(&format!("{kind} {name}"), RECORD_REF_LABEL_MAX_CHARS)
}

/// `text` on one line, every run of whitespace or control characters one
/// space, cut to `max_chars` with a closing ellipsis.
pub fn bounded(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut count = 0;
    let mut gap = false;
    for ch in text.chars() {
        if ch.is_whitespace() || ch.is_control() {
            gap = count > 0;
            continue;
        }
        let needed = usize::from(gap) + 1;
        if count + needed > max_chars {
            if count >= max_chars {
                out.pop();
            }
            out.push('…');
            return out;
        }
        if gap {
            out.push(' ');
            count += 1;
            gap = false;
        }
        out.push(ch);
        count += 1;
    }
    out
}
