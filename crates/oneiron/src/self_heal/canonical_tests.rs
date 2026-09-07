//! Regressions for the released diagnostic wire grammar.

use super::*;

#[test]
fn diagnostic_rejects_noncanonical_body_bytes() -> Result<()> {
    let canonical = encode_diagnostic_event_body(&sample_event())?;
    validate_diagnostic_event_body_bytes(&canonical)?;

    let mut entries = body_entries(&canonical);
    entries.swap(0, 1);
    let reordered = encode_entries(entries);
    assert_ne!(reordered, canonical);
    assert_rejected(&reordered, "reordered body keys");
    assert!(validate_diagnostic_event_body_bytes(&reordered).is_err());

    // A wider integer marker preserves the decoded value, but not its bytes.
    let mut key = Vec::new();
    rmpv::encode::write_value(&mut key, &Value::from("schema_version")).unwrap();
    let offset = canonical
        .windows(key.len())
        .position(|part| part == key)
        .unwrap()
        + key.len();
    assert_eq!(canonical[offset], 0x01);
    let mut wide = canonical[..offset].to_vec();
    wide.extend_from_slice(&[0xCC, 0x01]);
    wide.extend_from_slice(&canonical[offset + 1..]);
    decode_diagnostic_event_body(&wide)?;
    assert_eq!(
        validate_diagnostic_event_body_bytes(&wide).unwrap_err().kind(),
        ErrorKind::InvalidDiagnosticBody
    );

    let uppercase = seed_id(0xAB).to_hex().to_uppercase();
    for (key, value) in [
        ("actor_ref", Value::from(uppercase.clone())),
        ("evidence_refs", Value::Array(vec![Value::from(uppercase)])),
    ] {
        let mut entries = body_entries(&canonical);
        set_key(&mut entries, key, value);
        assert_rejected(&encode_entries(entries), "uppercase entity ref");
    }
    Ok(())
}

#[test]
fn diagnostic_escape_requires_exact_writer_form() -> Result<()> {
    let canonical = encode_diagnostic_event_body(&sample_event())?;
    for hostile in [
        r"\u{9}",
        r"\u{009}",
        r"\u{00009}",
        r"\u{00ad}",
        r"\u{00aD}",
        r"\u{000AD}",
        r"\u{D800}",
        r"\u{DFFF}",
        r"\u{110000}",
        r"\u{FFFFFF}",
        r"\u{0000009}",
        r"\u{0041}",
        r"\u{005C}",
        r"\u{1F600}",
        r"\u{E0000}",
        r"\u{0E0001}",
        r"\u{}",
        r"\u{0009",
        r"\u{0009}\u{41}",
        r"\u{e007f}",
    ] {
        let mut entries = body_entries(&canonical);
        set_key(&mut entries, "untrusted_detail", Value::from(hostile));
        let bytes = encode_entries(entries);
        assert_rejected(&bytes, hostile);
        assert!(validate_diagnostic_event_body_bytes(&bytes).is_err());

        // At the raw-author door the same text is literal, not a control escape.
        let mut draft = sample_event();
        draft.untrusted_detail = Some(hostile.to_owned());
        let bytes = encode_diagnostic_event_body(&draft)?;
        let decoded = validate_diagnostic_event_body_bytes(&bytes)?;
        assert_eq!(decoded.untrusted_detail, Some(hostile.replace('\\', "\\\\")));
        assert_eq!(encode_stored_diagnostic_event_body(&decoded)?, bytes);
    }
    Ok(())
}

#[test]
fn raw_controls_and_literal_escape_text_keep_distinct_addresses() -> Result<()> {
    for scalar in ['\t', '\u{AD}', '\u{202E}', '\u{E0001}', '\u{E007F}'] {
        let mut raw = sample_event();
        raw.untrusted_detail = Some(scalar.to_string());
        let escaped = format!("\\u{{{:04X}}}", scalar as u32);
        let mut literal = raw.clone();
        literal.untrusted_detail = Some(escaped.clone());
        let raw_body = encode_diagnostic_event_body(&raw)?;
        let literal_body = encode_diagnostic_event_body(&literal)?;
        assert_ne!(raw_body, literal_body);
        assert_ne!(
            diagnostic_event_id(&raw.detector_id, &raw_body),
            diagnostic_event_id(&literal.detector_id, &literal_body)
        );
        for (body, detail) in [
            (&raw_body, escaped.clone()),
            (&literal_body, format!("\\{escaped}")),
        ] {
            let decoded = validate_diagnostic_event_body_bytes(body)?;
            assert_eq!(decoded.untrusted_detail, Some(detail));
            assert_eq!(encode_stored_diagnostic_event_body(&decoded)?, *body);
        }
        let mut entries = body_entries(&raw_body);
        set_key(
            &mut entries,
            "untrusted_detail",
            Value::from(scalar.to_string()),
        );
        assert_rejected(&encode_entries(entries), "raw forbidden scalar");
    }
    Ok(())
}
