//! Field readers the history decoders share: times and text.

use serde_json::Value;

/// A JSON string field, when present and non-empty.
pub(super) fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

/// RFC 3339 text, or Unix seconds as a number (ChatGPT writes float seconds),
/// as Unix milliseconds.
pub(super) fn time_ms(value: &Value) -> Option<u64> {
    if let Some(text) = value.as_str() {
        let time = chrono::DateTime::parse_from_rfc3339(text).ok()?;
        return u64::try_from(time.timestamp_millis()).ok();
    }
    let seconds = value.as_f64().filter(|seconds| seconds.is_finite())?;
    let millis = (seconds * 1000.0).round();
    (millis >= 0.0 && millis < u64::MAX as f64).then_some(millis as u64)
}

/// [`time_ms`] of a field.
pub(super) fn time_field(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(time_ms)
}

/// The text blocks of a content array joined by blank lines, the way a chat
/// shows consecutive text parts.
pub(super) fn join_texts(parts: &[&str]) -> String {
    let mut out = String::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        out.push_str(part);
    }
    out
}
