//! Core half of `store::diagnostic_record::untrusted_text`: its store-layer items live in `oneiron_store::diagnostic_record::untrusted_text` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::diagnostic_record::untrusted_text::*;

use super::event::invalid_diagnostic;
use crate::error::Result;

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
