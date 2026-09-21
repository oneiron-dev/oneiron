//! Stable L2 prefix framing shared by every context-pack format.

use crate::context_pack::{L2BaseSummary, PackFormat};

pub(super) fn with_l2_prefix(
    summary: Option<&L2BaseSummary>,
    format: PackFormat,
    delta: Vec<u8>,
) -> Vec<u8> {
    let Some(summary) = summary else { return delta };
    let prefix = serde_json::to_string(summary).expect("L2 summary JSON");
    let delta = String::from_utf8(delta).expect("context pack UTF-8");
    match format {
        PackFormat::Json
        | PackFormat::OpenaiCompat
        | PackFormat::AnthropicMessages
        | PackFormat::Gemini => format!("{{\"l2_base\":{prefix},\"delta\":{delta}}}").into_bytes(),
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
    }
}
