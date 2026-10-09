//! Regressions for the released diagnostic wire grammar.

use super::*;

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
        assert_eq!(
            decoded.untrusted_detail,
            Some(hostile.replace('\\', "\\\\"))
        );
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

/// A content address has to pin BYTES, not just values: the write door
/// re-encodes what it decoded and demands byte equality, so a body that means
/// the right thing in the wrong spelling — re-ordered keys, a wider
/// MessagePack marker than the value needs, an uppercase ref — is refused
/// instead of being stored as a second byte string for one event.
#[test]
fn non_canonical_spellings_are_refused() {
    let canonical = encode_diagnostic_event_body(&sample_event()).expect("sample encodes");
    validate_diagnostic_event_body_bytes(&canonical).expect("the canonical body is accepted");

    // 1. Re-ordered keys: the same 17 pairs, spelled in a different order.
    let mut entries = body_entries(&canonical);
    entries.swap(0, 1);
    let reordered = encode_entries(entries);
    assert_ne!(reordered, canonical, "the fixture really is re-ordered");
    assert_rejected(&reordered, "re-ordered body keys");
    assert_eq!(
        validate_diagnostic_event_body_bytes(&reordered)
            .expect_err("re-ordered keys must be refused")
            .kind(),
        ErrorKind::InvalidDiagnosticBody
    );

    // 2. An alternate wire marker: `schema_version`'s 1 written as a uint8
    // (0xCC 0x01) instead of the positive fixint it canonically is. This
    // decodes to the same value, so only the byte-equality gate catches it.
    let mut key_bytes = Vec::new();
    rmpv::encode::write_value(&mut key_bytes, &Value::from("schema_version")).expect("key encodes");
    let at = canonical
        .windows(key_bytes.len())
        .position(|window| window == key_bytes)
        .expect("the schema_version key is present")
        + key_bytes.len();
    assert_eq!(canonical[at], 0x01, "1 is canonically a positive fixint");
    let mut wide_marker = canonical[..at].to_vec();
    wide_marker.extend_from_slice(&[0xCC, 0x01]);
    wide_marker.extend_from_slice(&canonical[at + 1..]);
    assert_ne!(wide_marker, canonical, "the fixture really is re-marked");
    decode_diagnostic_event_body(&wide_marker).expect("a marker alias still decodes");
    assert_eq!(
        validate_diagnostic_event_body_bytes(&wide_marker)
            .expect_err("an alternate wire marker must be refused")
            .kind(),
        ErrorKind::InvalidDiagnosticBody
    );

    // 3. Uppercase refs: `EntityId::from_hex` is case-insensitive, so decode
    // pins the lowercase spelling itself rather than leaning on the gate.
    // Seed 0xAB, so the hex actually carries letters to upcase.
    let lettered = seed_id(0xAB).to_hex();
    let shouted = lettered.to_uppercase();
    assert_ne!(lettered, shouted, "the fixture ref really has letters");

    let mut entries = body_entries(&canonical);
    set_key(&mut entries, "actor_ref", Value::from(shouted.clone()));
    assert_rejected(&encode_entries(entries), "an uppercase actor ref");

    let mut entries = body_entries(&canonical);
    set_key(
        &mut entries,
        "evidence_refs",
        Value::Array(vec![Value::from(shouted)]),
    );
    assert_rejected(&encode_entries(entries), "an uppercase evidence ref");
}
