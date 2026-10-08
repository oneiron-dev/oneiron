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
            if let Some(limit) = fields.get(key).and_then(JsonValue::as_u64) {
                fields.remove(key);
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
