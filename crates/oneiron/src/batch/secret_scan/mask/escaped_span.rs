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
    leaf.windows(bytes.len())
        .enumerate()
        .filter(|(_, window)| *window == bytes)
        .map(|(at, _)| at..at + bytes.len())
        .collect()
}
