use super::{MemoryReasonEvidence, MemoryReasonFormat, quoted, render_evidence};
use serde_json::Value;

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
    assert_eq!(encoded.lines().count(), 3);
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
