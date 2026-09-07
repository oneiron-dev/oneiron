use serde_json::{Value, json};

use super::{MemoryReasonEvidence, MemoryReasonFormat};

/// Renders the evidence in the requested format.
///
/// This route's own renderer, not the context-pack serializer: that one
/// serializes a `ContextPack`, which this read does not build, and reshaping
/// these rows into one to borrow its writers would invent pack accounting the
/// read never earned.
pub(crate) fn render_evidence(
    format: MemoryReasonFormat,
    evidence: &[MemoryReasonEvidence],
) -> String {
    match format {
        MemoryReasonFormat::Json => render_json(evidence),
        MemoryReasonFormat::Markdown => render_markdown(evidence),
        MemoryReasonFormat::Plaintext => render_plaintext(evidence),
        MemoryReasonFormat::Toon => render_toon(evidence),
        MemoryReasonFormat::Yaml => render_yaml(evidence),
    }
}

fn render_json(evidence: &[MemoryReasonEvidence]) -> String {
    let rows: Vec<Value> = evidence
        .iter()
        .map(|row| {
            json!({
                "shortId": row.short_id,
                "kind": row.kind,
                "text": row.text,
                "confidence": row.confidence,
            })
        })
        .collect();
    serde_json::to_string_pretty(&Value::Array(rows)).unwrap_or_else(|_| "[]".to_owned())
}

fn render_markdown(evidence: &[MemoryReasonEvidence]) -> String {
    let mut out = String::new();
    for row in evidence {
        out.push_str(&format!(
            "- **{}** ({}) — {}\n",
            row.short_id, row.kind, row.text
        ));
    }
    out
}

fn render_plaintext(evidence: &[MemoryReasonEvidence]) -> String {
    let mut out = String::new();
    for row in evidence {
        out.push_str(&format!("{} ({}): {}\n", row.short_id, row.kind, row.text));
    }
    out
}

/// TOON tabular rows: one header carrying the row count and field names, then
/// one comma-separated line per row.
fn render_toon(evidence: &[MemoryReasonEvidence]) -> String {
    let mut out = format!("evidence[{}]{{shortId,kind,text}}:", evidence.len());
    for row in evidence {
        out.push_str("\n  ");
        out.push_str(&quoted(&row.short_id));
        out.push(',');
        out.push_str(&quoted(&row.kind));
        out.push(',');
        out.push_str(&quoted(&row.text));
    }
    out.push('\n');
    out
}

fn render_yaml(evidence: &[MemoryReasonEvidence]) -> String {
    let mut out = String::new();
    for row in evidence {
        out.push_str(&format!("- shortId: {}\n", quoted(&row.short_id)));
        out.push_str(&format!("  kind: {}\n", quoted(&row.kind)));
        out.push_str(&format!("  text: {}\n", quoted(&row.text)));
    }
    out
}

/// Always-quoted scalar, escaped. Both TOON and YAML accept a quoted string
/// everywhere they accept a bare one, so quoting unconditionally removes a
/// whole class of "this value happened to contain a separator" bug at the cost
/// of two characters a row.
fn quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}
