//! JSON merge outcome decoding for the scoped consolidation judge.

use super::*;

pub(super) enum MergeResolution {
    Merge {
        value: Value,
        candidate_ref: Option<EntityId>,
    },
    Accumulate,
    Escalate,
}

pub(super) fn decode_merge_resolution(response: &LlmResponse) -> Result<MergeResolution> {
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let parsed: serde_json::Value = serde_json::from_str(text.trim())
        .map_err(|_| invalid_consolidation("merge response must be JSON"))?;
    match parsed.get("resolution").and_then(|value| value.as_str()) {
        // With no prior head in scope, supersede degrades to merge (D7: at
        // most one prior head; the promotion writer owns the supersession).
        Some("merge" | "supersede") => Ok(MergeResolution::Merge {
            candidate_ref: parsed
                .get("candidate_ref")
                .map(|value| {
                    value
                        .as_str()
                        .and_then(|id| EntityId::from_hex(id).ok())
                        .ok_or_else(|| invalid_consolidation("invalid merge candidate identity"))
                })
                .transpose()?,
            value: json_to_rmpv(parsed.get("value").unwrap_or(&serde_json::Value::Null)),
        }),
        Some("accumulate") => Ok(MergeResolution::Accumulate),
        Some("escalate") => Ok(MergeResolution::Escalate),
        _ => Err(invalid_consolidation("unknown merge resolution")),
    }
}
