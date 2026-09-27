use super::*;

/// Hedge vocabulary over calibrated-absolute confidence (scour:A176 —
/// never rank-relative).
pub(super) fn hedge_bucket_for(confidence: f32) -> &'static str {
    if confidence >= 0.9 {
        "confident"
    } else if confidence >= 0.7 {
        "likely"
    } else if confidence >= 0.4 {
        "tentative"
    } else {
        "uncertain"
    }
}

/// Maps the OF-096 format strings (`toon|md|json|yaml|txt`) to the pack
/// serializer formats.
pub(in crate::memory) fn parse_pack_format(format: &str) -> MemoryResult<PackFormat> {
    match format {
        "openai-compat" => Ok(PackFormat::OpenaiCompat),
        "anthropic-messages" => Ok(PackFormat::AnthropicMessages),
        "gemini" => Ok(PackFormat::Gemini),
        "json" => Ok(PackFormat::Json),
        "yaml" => Ok(PackFormat::Yaml),
        "toon" => Ok(PackFormat::Toon),
        "md" => Ok(PackFormat::Markdown),
        "txt" => Ok(PackFormat::Plaintext),
        other => Err(MemoryError::bad_request_with(
            format!("unknown pack format {other:?}"),
            &["Use one of: toon, md, json, yaml, txt, openai-compat, anthropic-messages, gemini."],
        )),
    }
}

pub(super) fn value_text_of(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

pub(in crate::memory) fn truncate_text(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_owned()
    } else {
        let mut out: String = text.chars().take(max_chars).collect();
        out.push('…');
        out
    }
}
