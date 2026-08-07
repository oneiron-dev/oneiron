use super::*;

/// ONE-1132 OWNER-DECISION literals: reason wire bytes and their
/// soft/hard effect class. A transposed byte table (e.g. gdpr=2) fails
/// here, not at a remote receiver.
#[test]
fn tombstone_reason_wire_bytes_match_pinned_table() {
    let cases = [
        (TombstoneReason::UserDelete, 1_u8, false),
        (TombstoneReason::UserHardDelete, 2, true),
        (TombstoneReason::GdprDelete, 3, true),
        (TombstoneReason::PolicyDelete, 4, true),
    ];
    for (reason, wire_byte, hard) in cases {
        assert_eq!(reason.wire_byte(), wire_byte, "{reason:?} wire byte");
        assert_eq!(
            TombstoneReason::from_wire_byte(wire_byte),
            Some(reason),
            "{reason:?} round-trip"
        );
        assert_eq!(reason.is_hard(), hard, "{reason:?} effect class");
    }
    // Byte 0 is RESERVED (= hard) and every byte above the table is
    // unknown (= hard): neither may decode to a known reason.
    for unknown in [0_u8, 5, 17, 120, 255] {
        assert_eq!(
            TombstoneReason::from_wire_byte(unknown),
            None,
            "byte {unknown} must not decode to a known reason"
        );
    }
}

#[test]
fn delete_reason_maps_onto_wire_reason() {
    let cases = [
        (DeleteReason::UserDelete, TombstoneReason::UserDelete),
        (
            DeleteReason::UserHardDelete,
            TombstoneReason::UserHardDelete,
        ),
        (DeleteReason::GdprDelete, TombstoneReason::GdprDelete),
        (DeleteReason::PolicyDelete, TombstoneReason::PolicyDelete),
    ];
    for (delete_reason, wire_reason) in cases {
        assert_eq!(TombstoneReason::from(delete_reason), wire_reason);
    }
}

/// Pinned layout `[reason:1][deleted_at:8 LE][request_id:16]` asserted
/// byte-by-byte: a big-endian or offset-shifted encoder fails here.
#[test]
fn tombstone_value_v2_encodes_exact_byte_layout() {
    let value = TombstoneValueV2 {
        reason: TombstoneReason::GdprDelete,
        deleted_at: 0x0102_0304_0506_0708,
        request_id: *b"0123456789abcdef",
    };
    let encoded = value.encode();
    assert_eq!(encoded.len(), TOMBSTONE_VALUE_V2_LEN);
    assert_eq!(encoded[0], 3, "offset 0 = reason wire byte");
    assert_eq!(
        &encoded[1..9],
        &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
        "offsets 1..9 = deleted_at u64 LITTLE-endian"
    );
    assert_eq!(
        &encoded[9..25],
        b"0123456789abcdef",
        "offsets 9..25 = raw request UUID bytes"
    );
}

/// Table-driven decode: every non-v2-soft shape MUST decode as HARD
/// (fail-closed: over-purge, never under-delete). The expectations are
/// written as literals, never round-tripped through the encoder.
#[test]
fn decode_tombstone_value_table() {
    struct Case {
        name: &'static str,
        input: Vec<u8>,
        want_reason: Option<TombstoneReason>,
        want_hard: bool,
        want_deleted_at: u64,
        want_request_id: Option<[u8; 16]>,
    }

    let v2 = |reason_byte: u8| -> Vec<u8> {
        let mut out = vec![reason_byte];
        out.extend_from_slice(&[0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00]);
        out.extend_from_slice(&[0xA5; 16]);
        out
    };

    let cases = [
        Case {
            name: "v2 soft user_delete",
            input: v2(1),
            want_reason: Some(TombstoneReason::UserDelete),
            want_hard: false,
            want_deleted_at: 0xDEAD_BEEF,
            want_request_id: Some([0xA5; 16]),
        },
        Case {
            name: "v2 hard user_hard_delete",
            input: v2(2),
            want_reason: Some(TombstoneReason::UserHardDelete),
            want_hard: true,
            want_deleted_at: 0xDEAD_BEEF,
            want_request_id: Some([0xA5; 16]),
        },
        Case {
            name: "v2 hard gdpr_delete",
            input: v2(3),
            want_reason: Some(TombstoneReason::GdprDelete),
            want_hard: true,
            want_deleted_at: 0xDEAD_BEEF,
            want_request_id: Some([0xA5; 16]),
        },
        Case {
            name: "v2 hard policy_delete",
            input: v2(4),
            want_reason: Some(TombstoneReason::PolicyDelete),
            want_hard: true,
            want_deleted_at: 0xDEAD_BEEF,
            want_request_id: Some([0xA5; 16]),
        },
        Case {
            name: "reserved byte 0 decodes as hard",
            input: v2(0),
            want_reason: None,
            want_hard: true,
            want_deleted_at: 0xDEAD_BEEF,
            want_request_id: Some([0xA5; 16]),
        },
        Case {
            name: "unknown reason byte 5 decodes as hard",
            input: v2(5),
            want_reason: None,
            want_hard: true,
            want_deleted_at: 0xDEAD_BEEF,
            want_request_id: Some([0xA5; 16]),
        },
        Case {
            name: "unknown reason byte 255 decodes as hard",
            input: v2(255),
            want_reason: None,
            want_hard: true,
            want_deleted_at: 0xDEAD_BEEF,
            want_request_id: Some([0xA5; 16]),
        },
        Case {
            name: "legacy 8-byte value decodes as hard with LE deleted_at",
            input: vec![0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00],
            want_reason: None,
            want_hard: true,
            want_deleted_at: 0xDEAD_BEEF,
            want_request_id: None,
        },
        Case {
            name: "empty value decodes as hard",
            input: Vec::new(),
            want_reason: None,
            want_hard: true,
            want_deleted_at: 0,
            want_request_id: None,
        },
        Case {
            name: "24-byte value decodes as hard",
            input: vec![1; 24],
            want_reason: None,
            want_hard: true,
            want_deleted_at: 0,
            want_request_id: None,
        },
        Case {
            name: "26-byte value decodes as hard",
            input: vec![1; 26],
            want_reason: None,
            want_hard: true,
            want_deleted_at: 0,
            want_request_id: None,
        },
    ];

    for case in cases {
        let decoded = decode_tombstone_value(&case.input);
        assert_eq!(decoded.reason, case.want_reason, "{}: reason", case.name);
        assert_eq!(decoded.is_hard(), case.want_hard, "{}: effect", case.name);
        assert_eq!(
            decoded.deleted_at, case.want_deleted_at,
            "{}: deleted_at",
            case.name
        );
        assert_eq!(
            decoded.request_id, case.want_request_id,
            "{}: request_id",
            case.name
        );
    }
}

/// The window label used by the `pt:` marker must follow the pinned
/// ARCH-0023b `YYYY-MM` format and clamp in BOTH feature sets —
/// `sync::types::WindowKey::from_timestamp` delegates here.
#[test]
fn window_label_format_and_clamp() {
    // 2026-02-15 ≈ unix 1_771_027_200 (same literal as the sync-side
    // WindowKey test, so the delegation cannot drift unnoticed).
    assert_eq!(window_label_from_timestamp(1_771_027_200), "2026-02");
    assert_eq!(window_label_from_timestamp(0), "1970-01");
    for ts in [i64::MAX as u64, u64::MAX] {
        assert_eq!(window_label_from_timestamp(ts), "9999-12", "ts={ts}");
    }
}

#[test]
fn leap_year_boundaries_keep_feb_29_in_february_window() {
    assert!(!is_leap_year(2023), "ordinary year");
    assert!(is_leap_year(2024), "divisible-by-4 leap year");
    assert!(!is_leap_year(2100), "century year not divisible by 400");
    assert!(is_leap_year(2000), "century year divisible by 400");

    // 2024-02-29 00:00:00 UTC and 2024-03-01 00:00:00 UTC.
    assert_eq!(window_label_from_timestamp(1_709_164_800), "2024-02");
    assert_eq!(window_label_from_timestamp(1_709_251_200), "2024-03");
}

#[test]
fn pending_tombstone_key_layout() {
    let id = EntityId::from_bytes([0x7E; 16]).expect("valid id");
    assert_eq!(
        pending_tombstone_key("2026-02", &id),
        format!("pt:2026-02:{}", id.to_hex())
    );
}

/// Pinned `dt:` marker: GLOBAL key (no window segment) and the exact
/// 25 B `[reason:1][deleted_at:8 LE][request_id:16]` value, asserted as
/// literals — including the destructive-default/NIL fallbacks for
/// legacy/malformed wire shapes.
#[test]
fn local_hard_delete_marker_layout() {
    let id = EntityId::from_bytes([0x7E; 16]).expect("valid id");
    assert_eq!(
        local_hard_delete_key(&id),
        format!("dt:{}", id.to_hex()),
        "key must be global — deliberately NO window segment"
    );
    assert_eq!(local_hard_delete_key(&id).len(), 3 + 32);

    // Known hard reason: wire fields verbatim.
    let mut wire = vec![3_u8]; // gdpr_delete
    wire.extend_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());
    wire.extend_from_slice(&[0xA5; 16]);
    let value = decode_tombstone_value(&wire).local_hard_delete_marker_value();
    assert_eq!(value.len(), TOMBSTONE_VALUE_V2_LEN);
    assert_eq!(value[0], 3, "offset 0 = reason wire byte");
    assert_eq!(
        &value[1..9],
        &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
        "offsets 1..9 = deleted_at u64 LITTLE-endian"
    );
    assert_eq!(&value[9..25], &[0xA5; 16], "offsets 9..25 = request id");

    // Malformed shape: destructive default reason + zeroed fields.
    let value = decode_tombstone_value(&[]).local_hard_delete_marker_value();
    assert_eq!(value[0], 2, "fallback reason = user_hard_delete");
    assert_eq!(&value[1..9], &[0_u8; 8]);
    assert_eq!(&value[9..25], &[0_u8; 16], "fallback request id = NIL");
}

/// ONE-1140 (OD-6) attestation transcript literal, verified against the
/// engine's signer with a FIXED key and a hand-assembled transcript:
/// `b"oneiron/receipt-att/v1" || entity_id:16 || envelope_header:25
/// ([type 120][3 × u64 BE]) || body-with-verification-EMPTY` — where the
/// empty-verification tail is rebuilt by SPLICING the stored body at the
/// verification value and substituting fixmap(0) (0x80). A wrong domain
/// string, header endianness, splice point, or att_ key ordering fails
/// here against real Ed25519 verification.
#[test]
fn receipt_attestation_transcript_literal() {
    use ed25519_dalek::{Signature, SigningKey, Verifier};

    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let identity = crate::identity::DeviceIdentity {
        client_id: 0x0123_4567_89ab_cdef,
        signing_key: signing_key.clone(),
    };
    let receipt_id = EntityId::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    let subject = EntityId::from_hex("101112131415161718191a1b1c1d1e1f").unwrap();
    let input = RedactionReceiptInput {
        request_id: "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5b".to_owned(),
        scope: RedactionScope::entity(&subject),
        reason: DeleteReason::GdprDelete,
        requested_at: 100,
        soft_complete_at: 101,
        hard_purge_complete_at: 0x0102_0304_0506_0708,
        sweep_queued_at: Some(102),
    };
    let body = encode_redaction_audit_receipt(input, &receipt_id, &identity).unwrap();

    // The verification map must be the FINAL entry in bytes, its four
    // att_ keys in sorted (BTreeMap) order. Locate the value by the
    // fixstr(12) "verification" key header — the splice point literal.
    let key_pattern: &[u8] = b"\xacverification";
    let key_pos = body
        .windows(key_pattern.len())
        .rposition(|window| window == key_pattern)
        .expect("verification key present");
    let value_offset = key_pos + key_pattern.len();
    assert_eq!(
        body[value_offset], 0x84,
        "verification value is a fixmap(4) of the att_ entries"
    );

    // Parse the verification map and pin the att_ literals.
    let parsed: rmpv::Value = rmpv::decode::read_value(&mut &body[..]).unwrap();
    let entries = match parsed {
        rmpv::Value::Map(entries) => entries,
        other => panic!("body must be a map, got {other:?}"),
    };
    let (last_key, last_value) = entries.last().expect("non-empty");
    assert_eq!(
        last_key.as_str(),
        Some("verification"),
        "verification must be the final body map entry (tail-splice pin)"
    );
    let att = match last_value {
        rmpv::Value::Map(att) => att,
        other => panic!("verification must be a map, got {other:?}"),
    };
    let att_keys: Vec<&str> = att.iter().filter_map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        att_keys,
        vec!["att_client", "att_pk", "att_sig", "att_v"],
        "att_ entries in sorted (BTreeMap) byte order"
    );
    assert_eq!(att[0].1.as_str(), Some("0123456789abcdef"));
    assert_eq!(
        att[1].1.as_str().unwrap(),
        hex_lower(&signing_key.verifying_key().to_bytes())
    );
    assert_eq!(att[3].1.as_str(), Some("1"));

    // Hand-assemble the transcript per the OD-6 literals and verify the
    // embedded signature with real Ed25519.
    let mut msg = Vec::new();
    msg.extend_from_slice(b"oneiron/receipt-att/v1");
    msg.extend_from_slice(receipt_id.as_bytes());
    msg.push(crate::registry::ENTITY_TYPE_REDACTION_AUDIT);
    for _ in 0..3 {
        // occurred_start == occurred_end == learned_at, u64 BE.
        msg.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
    }
    msg.extend_from_slice(&body[..value_offset]);
    msg.push(0x80); // verification = {} in the signed tail
    let sig_hex = att[2].1.as_str().unwrap();
    assert_eq!(sig_hex.len(), 128);
    let sig_bytes: Vec<u8> = (0..128)
        .step_by(2)
        .map(|i| u8::from_str_radix(&sig_hex[i..i + 2], 16).unwrap())
        .collect();
    let signature = Signature::from_bytes(&sig_bytes.try_into().unwrap());
    signing_key
        .verifying_key()
        .verify(&msg, &signature)
        .expect("att_sig must verify over the hand-assembled OD-6 transcript");

    // And the shared header helper emits exactly the bytes the test
    // assembled (the signer/storage single assembly point).
    assert_eq!(
        &receipt_envelope_header(0x0102_0304_0506_0708)[..],
        &msg[38..63]
    );
}
