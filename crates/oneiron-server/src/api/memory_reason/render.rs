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
            // JSON-compatible Unicode escapes work in both quoted formats.
            // Escape YAML line separators too, to avoid scalar normalization.
            ch if ch.is_control()
                || matches!(ch, '\u{2028}' | '\u{2029}' | '\u{fffe}' | '\u{ffff}') =>
            {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            }
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control_text() -> String {
        let mut text = String::from("quotes \" and slash \\ comma, colon: Unicode 雪 ");
        for code in (0..=0x1f).chain(0x7f..=0x9f) {
            text.push(char::from_u32(code).unwrap());
        }
        text.push_str("\u{2028}\u{2029}\u{fffe}\u{ffff}");
        text
    }

    fn evidence() -> Vec<MemoryReasonEvidence> {
        let text = control_text();
        vec![MemoryReasonEvidence {
            short_id: text.clone(),
            kind: text.clone(),
            text,
            confidence: 1.0,
        }]
    }

    #[test]
    fn quoted_controls_roundtrip_without_literal_controls() {
        let text = control_text();
        let encoded = quoted(&text);
        assert!(!encoded.chars().any(char::is_control));
        assert!(encoded.contains("\\u0008"));
        assert!(encoded.contains("\\u000c"));
        assert!(encoded.contains("\\n"));
        assert!(encoded.contains("\\r"));
        assert!(encoded.contains("\\t"));
        assert_eq!(serde_json::from_str::<String>(&encoded).unwrap(), text);
        assert_eq!(serde_yaml_ng::from_str::<String>(&encoded).unwrap(), text);
    }

    #[test]
    fn yaml_evidence_controls_roundtrip_all_quoted_fields() {
        let evidence = evidence();
        let encoded = render_evidence(MemoryReasonFormat::Yaml, &evidence);
        let decoded: Value = serde_yaml_ng::from_str(&encoded).unwrap();
        for field in ["shortId", "kind", "text"] {
            assert_eq!(decoded[0][field], evidence[0].text);
        }
    }

    #[test]
    fn toon_evidence_controls_roundtrip_quoted_row() {
        let evidence = evidence();
        let encoded = render_evidence(MemoryReasonFormat::Toon, &evidence);
        let mut lines = encoded.lines();
        assert_eq!(lines.next(), Some("evidence[1]{shortId,kind,text}:"));
        // These always-quoted tabular fields use JSON-compatible escapes.
        // Parse the row as an array to check separators and scalar roundtrip,
        // not as a claim that this is a full TOON decoder.
        let row = lines.next().unwrap().trim_start();
        assert!(!row.chars().any(char::is_control));
        let decoded: Vec<String> = serde_json::from_str(&format!("[{row}]")).unwrap();
        assert_eq!(decoded, vec![evidence[0].text.clone(); 3]);
        assert!(lines.next().is_none());
    }
}

#[cfg(test)]
#[path = "render_tests.rs"]
mod render_tests;
