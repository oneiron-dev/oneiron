//! Reasoning leaves a MESSAGE read whole or not at all.

use crate::ContentPart;
use crate::store::witness_message_body::StoredMessagePart;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct MessageParts {
    parts: Option<Vec<StoredMessagePart>>,
}

/// Keep each original position, but never serve reasoning with a redacted
/// text, signature or opaque payload. Custody handles still need a reveal.
pub(super) fn withhold_modified_reasoning_parts(stored: &[u8], served: &mut Value) {
    let Some(served) = served.get_mut("parts").and_then(Value::as_array_mut) else {
        return;
    };
    let Ok(MessageParts { parts: Some(parts) }) = rmp_serde::from_slice(stored) else {
        return;
    };
    for (original, served) in parts.into_iter().zip(served) {
        let StoredMessagePart::Inline(part @ ContentPart::Reasoning { .. }) = original else {
            continue;
        };
        match serde_json::to_value(part) {
            Ok(original) if original == *served => {}
            _ => *served = Value::Null,
        }
    }
}
