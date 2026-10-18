//! Untrusted detail-text validation and escaping.
//!
//! A code run's blocked receipt is the one carrier of an escaped detail leaf.
//! Diagnostics carry none: their invariant inputs are numbers and their
//! `untrusted_detail` key is always nil. A diagnostic stored before the owner
//! ruling of 2026-10-14 may hold a leaf; decode checks it here and drops it.

use super::event::invalid_diagnostic;
use crate::error::Result;

// ── untrusted detail ────────────────────────────────────────────────────────

/// Inclusive scalar ranges that must never reach a reader raw, beyond the C0
/// and C1 control classes `char::is_control` already covers.
///
/// These are the INVISIBLE ones: soft hyphen, the Arabic letter mark, the
/// Mongolian vowel separator, the zero-width space/joiner family, the line and
/// paragraph separators, the bidirectional embedding/override/isolate controls,
/// the deprecated format characters, the byte-order mark, the interlinear
/// annotation marks, and Unicode tag controls. Each is a way to make one string RENDER as a different
/// string, which is exactly the trick an untrusted detail leaf would be used
/// for if it were allowed to carry them.
const FORBIDDEN_TEXT_RANGES: [(char, char); 11] = [
    ('\u{00AD}', '\u{00AD}'),
    ('\u{061C}', '\u{061C}'),
    ('\u{180E}', '\u{180E}'),
    ('\u{200B}', '\u{200F}'),
    ('\u{2028}', '\u{2029}'),
    ('\u{202A}', '\u{202E}'),
    ('\u{2060}', '\u{206F}'),
    ('\u{FEFF}', '\u{FEFF}'),
    ('\u{FFF9}', '\u{FFFB}'),
    ('\u{E0001}', '\u{E0001}'),
    ('\u{E0020}', '\u{E007F}'),
];

/// Whether `scalar` is control or invisible-format data.
pub(super) fn is_forbidden_text_scalar(scalar: char) -> bool {
    if scalar.is_control() {
        return true;
    }
    for (start, end) in FORBIDDEN_TEXT_RANGES {
        if (start..=end).contains(&scalar) {
            return true;
        }
    }
    false
}

/// Renders `raw` as a control-free canonical leaf.
///
/// Every forbidden scalar becomes a VISIBLE `\u{XXXX}` escape and a literal
/// backslash becomes `\\`, so the escaping is unambiguous to read. The mapping
/// is TOTAL — it runs over every input, including one that already LOOKS
/// escaped — which is what makes it injective: a raw tab and the literal
/// eight-character text `\u{0009}` land on the two different leaves `\u{0009}`
/// and `\\u{0009}`, and therefore on two different event ids, instead of
/// colliding on one.
fn escape_untrusted_detail(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for scalar in raw.chars() {
        if scalar == '\\' {
            out.push_str("\\\\");
        } else if is_forbidden_text_scalar(scalar) {
            let code = scalar as u32;
            out.push_str(&format!("\\u{{{code:04X}}}"));
        } else {
            out.push(scalar);
        }
    }
    out
}

/// Whether `text` is already an escaped canonical leaf.
fn is_canonical_untrusted_detail(text: &str) -> bool {
    if text.chars().any(is_forbidden_text_scalar) {
        return false;
    }
    // Byte scanning is safe here: `\`, `u`, `{`, `}` and the hex digits are all
    // ASCII, and UTF-8 never encodes an ASCII byte inside a multi-byte
    // sequence.
    let bytes = text.as_bytes();
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            index += 1;
            continue;
        }
        match bytes.get(index + 1) {
            Some(b'\\') => index += 2,
            Some(b'u') => match escape_end(bytes, index) {
                Some(next) => index = next,
                None => return false,
            },
            _ => return false,
        }
    }
    true
}

/// End offset only for the writer's exact rendering of a forbidden scalar.
fn escape_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start + 2) != Some(&b'{') {
        return None;
    }
    let mut cursor = start + 3;
    while bytes.get(cursor).is_some_and(u8::is_ascii_hexdigit) {
        cursor += 1;
    }
    let digits = cursor - (start + 3);
    if !(4..=6).contains(&digits) || bytes.get(cursor) != Some(&b'}') {
        return None;
    }
    let hex = std::str::from_utf8(&bytes[start + 3..cursor]).ok()?;
    let code = u32::from_str_radix(hex, 16).ok()?;
    let scalar = char::from_u32(code)?;
    if !is_forbidden_text_scalar(scalar) || hex != format!("{code:04X}") {
        return None;
    }
    Some(cursor + 1)
}

/// Escapes ONE raw, author-supplied detail into its stored canonical leaf.
///
/// There is deliberately NO already-canonical passthrough. A passthrough makes
/// the raw → stored map non-injective: a raw tab and the literal
/// eight-character text `\u{0009}` would both store `\u{0009}`, so two
/// different findings would share one body and one content-addressed id, and
/// the text a reader sees would not say which of the two it came from.
///
/// Applying this twice is therefore NOT the identity, and must never happen. A
/// stored leaf is TERMINAL: readers get it back escaped and never unescaped,
/// and a stored leaf is re-checked with [`validate_untrusted_detail`] instead
/// of being escaped again.
///
/// A detail of any length is kept whole; filing a report measures the stored
/// leaf against `limits.blocked_detail_bytes`.
pub(crate) fn canonical_untrusted_detail(raw: &str) -> Result<String> {
    let canonical = escape_untrusted_detail(raw);
    validate_untrusted_detail(&canonical)?;
    Ok(canonical)
}

pub(crate) fn validate_untrusted_detail(text: &str) -> Result<()> {
    if text.is_empty() {
        return Err(invalid_diagnostic("untrusted_detail must not be empty"));
    }
    if text.chars().any(is_forbidden_text_scalar) {
        return Err(invalid_diagnostic("untrusted_detail hides control data"));
    }
    if !is_canonical_untrusted_detail(text) {
        return Err(invalid_diagnostic("untrusted_detail is not escaped"));
    }
    Ok(())
}
