//! Regressions for the released diagnostic wire grammar.

use super::*;

/// Owner ruling 2026-10-14 (fix 6): a diagnostic never carries world text.
/// Every leaf that could hold a row's words is refused at both write doors:
/// the draft encoder and the write door a replicated body arrives through. A
/// body stored before the ruling decodes with that text dropped.
#[test]
fn a_diagnostic_carries_no_row_text() {
    const ROW: &str = "sentinel-row-text-9d02: my sister's diagnosis";
    let canonical = encode_diagnostic_event_body(&sample_event()).expect("sample encodes");
    for (key, hostile) in [
        ("untrusted_detail", Value::from(ROW)),
        ("expected", Value::from(ROW)),
        (
            "actual",
            Value::Array(vec![Value::from(1_u64), Value::from(ROW)]),
        ),
        (
            "delta",
            Value::Map(vec![(Value::from(ROW), Value::from(1_u64))]),
        ),
    ] {
        let mut entries = body_entries(&canonical);
        set_key(&mut entries, key, hostile.clone());
        let bytes = encode_entries(entries);
        let read = decode_diagnostic_event_body(&bytes).expect("a stored body reads");
        assert!(!format!("{read:?}").contains("sentinel"), "{key}");
        assert!(
            validate_diagnostic_event_body_bytes(&bytes).is_err(),
            "{key}"
        );

        let mut draft = sample_event();
        match key {
            "expected" => draft.expected = hostile,
            "actual" => draft.actual = hostile,
            "delta" => draft.delta = hostile,
            _ => continue,
        }
        assert!(encode_diagnostic_event_body(&draft).is_err(), "{key}");
    }
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
