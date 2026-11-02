//! A structured value's JSON-escaped span in its leaf (FIX 1369).

use std::ops::Range;

use zeroize::Zeroizing;

/// Each place `value`'s JSON-escaped form sits in `leaf`: the value as
/// [`serde_json::to_string`] writes it, without its two surrounding quotes.
/// A value that is no UTF-8 has none.
pub(super) fn escaped_occurrences(leaf: &[u8], value: &[u8]) -> Vec<Range<usize>> {
    let Ok(text) = std::str::from_utf8(value) else {
        return Vec::new();
    };
    let Ok(quoted) = serde_json::to_string(text) else {
        return Vec::new();
    };
    let escaped = Zeroizing::new(quoted);
    let Some(inner) = escaped.get(1..escaped.len().saturating_sub(1)) else {
        return Vec::new();
    };
    if inner.is_empty() {
        return Vec::new();
    }
    let bytes = inner.as_bytes();
    // Only a place that opens with the escaped form's first byte is
    // compared whole (speed, FIX 12211).
    let Some(&first) = bytes.first() else {
        return Vec::new();
    };
    let mut spans = Vec::new();
    let mut from = 0;
    while let Some(rest) = leaf.get(from..).filter(|rest| rest.len() >= bytes.len()) {
        let Some(offset) = rest.iter().position(|&byte| byte == first) else {
            break;
        };
        let at = from + offset;
        from = at + 1;
        if leaf.get(at..at + bytes.len()) == Some(bytes) {
            spans.push(at..at + bytes.len());
        }
    }
    spans
}
