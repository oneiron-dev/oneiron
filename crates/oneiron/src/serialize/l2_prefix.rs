//! Stable L2 prefix framing shared by every context-pack format.

use crate::context_pack::{L2BaseSummary, PackFormat};

pub(super) fn with_l2_prefix(
    summary: Option<&L2BaseSummary>,
    format: PackFormat,
    delta: Vec<u8>,
) -> Vec<u8> {
    let Some(summary) = summary else { return delta };
    let prefix = serde_json::to_string(summary).expect("L2 summary JSON");
    if matches!(
        format,
        PackFormat::OpenaiCompat | PackFormat::AnthropicMessages | PackFormat::Gemini
    ) {
        return provider_prefix(&prefix, format, &delta);
    }
    let delta = String::from_utf8(delta).expect("context pack UTF-8");
    match format {
        PackFormat::Json => format!("{{\"l2_base\":{prefix},\"delta\":{delta}}}").into_bytes(),
        PackFormat::Yaml => {
            let mut out = format!("l2_base: {prefix}\ndelta:\n");
            for line in delta.lines() {
                out.push_str("  ");
                out.push_str(line);
                out.push('\n');
            }
            out.into_bytes()
        }
        PackFormat::Toon => {
            let scalar = serde_json::to_string(&prefix).expect("L2 TOON scalar");
            let mut out = format!("l2_base: {scalar}\ndelta:\n");
            for line in delta.lines() {
                out.push_str("  ");
                out.push_str(line);
                out.push('\n');
            }
            out.into_bytes()
        }
        PackFormat::Markdown | PackFormat::Plaintext => {
            format!("l2_base: {prefix}\n---delta\n{delta}").into_bytes()
        }
        PackFormat::OpenaiCompat | PackFormat::AnthropicMessages | PackFormat::Gemini => {
            unreachable!("provider prefix uses its native envelope above")
        }
    }
}

fn provider_prefix(prefix: &str, format: PackFormat, delta: &[u8]) -> Vec<u8> {
    let mut root: serde_json::Value = serde_json::from_slice(delta).expect("provider JSON");
    let field = if format == PackFormat::Gemini {
        "contents"
    } else {
        "messages"
    };
    let message = match format {
        PackFormat::OpenaiCompat => serde_json::json!({"role":"user","content":prefix}),
        PackFormat::AnthropicMessages => serde_json::json!({
            "role":"user","content":[{"type":"text","text":prefix}]
        }),
        PackFormat::Gemini => serde_json::json!({
            "role":"user","parts":[{"text":prefix}]
        }),
        _ => unreachable!("provider prefix requires a provider format"),
    };
    root[field]
        .as_array_mut()
        .expect("provider message array")
        .insert(0, message);
    serde_json::to_vec(&root).expect("provider value is serializable")
}
