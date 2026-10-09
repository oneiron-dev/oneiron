//! A provider's output ceiling on the wire. A configured `max_output_tokens`
//! bounds every call: it fills the request when the caller named no limit,
//! and a larger limit is cut down to it. Every spelling a request may carry
//! is folded into the one field the endpoint reads.
use serde_json::Value as JsonValue;

/// Where a request may name its output limit: the two wire spellings and
/// the engine's generic `max_output_tokens` param.
const LIMIT_KEYS: [&str; 3] = ["max_tokens", "max_completion_tokens", "max_output_tokens"];

#[derive(Clone, Copy, Debug)]
pub(super) struct OutputCap {
    /// The field the endpoint reads.
    pub(super) field: &'static str,
    /// The provider's configured ceiling.
    pub(super) ceiling: Option<u64>,
    /// Sent when neither the caller nor the provider names a limit, for a
    /// wire that requires one.
    pub(super) fallback: Option<u64>,
}

impl OutputCap {
    pub(super) fn apply(&self, body: &mut JsonValue) {
        let Some(fields) = body.as_object_mut() else {
            return;
        };
        let mut asked: Option<u64> = None;
        for key in LIMIT_KEYS {
            // Every spelling leaves the wire, parsed or not: an endpoint that
            // reads a spelling left behind would generate past the ceiling.
            if let Some(limit) = fields.remove(key).as_ref().and_then(token_count) {
                asked = Some(asked.map_or(limit, |seen| seen.min(limit)));
            }
        }
        let limit = match (asked, self.ceiling) {
            (Some(asked), Some(ceiling)) => Some(asked.min(ceiling)),
            (Some(asked), None) => Some(asked),
            (None, ceiling) => ceiling.or(self.fallback),
        };
        if let Some(limit) = limit {
            fields.insert(self.field.to_owned(), limit.into());
        }
    }
}

/// A limit as a token count, however the caller wrote the number: lenient
/// endpoints accept `4096.0` and `"4096"` as well as `4096`.
fn token_count(value: &JsonValue) -> Option<u64> {
    let number = match value {
        JsonValue::Number(number) => number.as_f64()?,
        JsonValue::String(text) => text.trim().parse::<f64>().ok()?,
        _ => return None,
    };
    // A fractional limit allows its whole tokens.
    (number.is_finite() && number >= 0.0).then_some(number as u64)
}
