use super::*;
use core::assert_matches;

#[test]
fn protocol_hello_wire_literals() {
    // Contract literals: the hello frame is EXACTLY
    // [TAG_PROTOCOL_HELLO=3, PROTOCOL_VERSION=7]. A drifted tag or
    // version byte is a silent wire break — assert the raw bytes.
    // Version pinned 1→2 by the ONE-1140 atomic wire train (OD-5):
    // lease frames + connect sequence + leases registry + attested
    // receipts land behind this single bump; v1 peers close 4006.
    // Version pinned 2→3 by FED-002 selector sync so v3 clients do not
    // negotiate successfully with pre-selector daemons.
    // Version pinned 3→4/5 by FED-005 scoped lease keys so v2/v3 clients
    // are rejected before they can quarantine scoped root `leases` rows.
    // Version pinned 4/5→6/7 by SYNC-EPH-1 because tag 1 payloads changed
    // from JSON awareness to Loro-native EphemeralStore bytes.
    assert_eq!(TAG_PROTOCOL_HELLO, 3, "hello tag byte is pinned to 3");
    assert_eq!(PROTOCOL_VERSION, 7, "wire protocol version is pinned to 7");
    assert_eq!(
        LEGACY_FULL_WINDOW_PROTOCOL_VERSION, 6,
        "legacy full-window version is pinned to 6"
    );
    assert_eq!(encode_protocol_hello(), vec![3u8, 7u8]);
    assert_eq!(encode_legacy_full_window_protocol_hello(), vec![3u8, 6u8]);
}

#[test]
fn window_subtag_literals() {
    assert_eq!(window_sub_tags::UPDATE, 0);
    assert_eq!(window_sub_tags::VV_REQUEST, 2);
    assert_eq!(window_sub_tags::VV_RESPONSE, 3);
    assert_eq!(window_sub_tags::SELECTOR_VV_REQUEST, 4);
}

#[test]
fn full_window_sync_wire_frames_remain_backward_compatible_under_selector_bump() {
    let vv_payload = [0xAA, 0xBB, 0xCC];
    let update_payload = [0x11, 0x22];
    let key = "2026-09";

    let vv_request = encode_window_sync(key, window_sub_tags::VV_REQUEST, &vv_payload)
        .into_result()
        .unwrap();
    assert_eq!(
        vv_request,
        [
            &[TAG_WINDOW_SYNC, 7],
            key.as_bytes(),
            &[window_sub_tags::VV_REQUEST],
            &vv_payload,
        ]
        .concat()
    );
    let (decoded_key, decoded_subtag, decoded_payload) =
        decode_window_sync(&vv_request[1..]).unwrap();
    assert_eq!(decoded_key, key);
    assert_eq!(decoded_subtag, window_sub_tags::VV_REQUEST);
    assert_eq!(decoded_payload, vv_payload);

    let vv_response = encode_window_sync(key, window_sub_tags::VV_RESPONSE, &vv_payload)
        .into_result()
        .unwrap();
    let (_, decoded_subtag, decoded_payload) = decode_window_sync(&vv_response[1..]).unwrap();
    assert_eq!(decoded_subtag, window_sub_tags::VV_RESPONSE);
    assert_eq!(decoded_payload, vv_payload);

    let update = encode_window_sync(key, window_sub_tags::UPDATE, &update_payload)
        .into_result()
        .unwrap();
    let (_, decoded_subtag, decoded_payload) = decode_window_sync(&update[1..]).unwrap();
    assert_eq!(decoded_subtag, window_sub_tags::UPDATE);
    assert_eq!(decoded_payload, update_payload);
}

/// ONE-1140 (OD-5) wire literals: TAG_LEASE_REQUEST=4 (105 B) and
/// TAG_LEASE_GRANTED=5 (18 B), BE scalars at pinned offsets. Byte-exact
/// round-trips plus exhaustive malformed-frame rejection — a transposed
/// field, LE flip, or length drift fails here, not at a peer.
#[test]
fn lease_frame_layout_literals() {
    assert_eq!(TAG_LEASE_REQUEST, 4, "lease request tag pinned to 4");
    assert_eq!(TAG_LEASE_GRANTED, 5, "lease granted tag pinned to 5");

    // LeaseRequest: [0x04][client_id:8 BE][pubkey:32][pop_sig:64].
    let pubkey = [0xAAu8; 32];
    let pop_sig = [0xBBu8; 64];
    let request = encode_lease_request(0x0102030405060708, &pubkey, &pop_sig);
    assert_eq!(request.len(), 105, "LeaseRequest frame is exactly 105 B");
    assert_eq!(request[0], 4);
    assert_eq!(
        &request[1..9],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        "client_id is u64 BE at offset 1"
    );
    assert_eq!(&request[9..41], &[0xAA; 32]);
    assert_eq!(&request[41..105], &[0xBB; 64][..]);
    let (cid, pk, sig) = decode_lease_request(&request[1..]).unwrap();
    assert_eq!(cid, 0x0102030405060708);
    assert_eq!(pk, pubkey);
    assert_eq!(sig, pop_sig);
    // Exhaustive length validation: truncated and trailing both reject.
    assert!(decode_lease_request(&request[1..104]).is_err());
    let mut long = request[1..].to_vec();
    long.push(0);
    assert!(decode_lease_request(&long).is_err());

    // LeaseGranted: [0x05][status:1][client_id:8 BE][expires_at:8 BE].
    let granted = encode_lease_granted(LEASE_STATUS_GRANTED, 0x0102030405060708, 0x11223344);
    assert_eq!(granted.len(), 18, "LeaseGranted frame is exactly 18 B");
    assert_eq!(granted[0], 5);
    assert_eq!(granted[1], 0x01, "granted status byte");
    assert_eq!(
        &granted[2..10],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    );
    assert_eq!(
        &granted[10..18],
        &0x11223344u64.to_be_bytes(),
        "expires_at is u64 BE at offset 10"
    );
    assert_eq!(
        decode_lease_granted(&granted[1..]).unwrap(),
        (LEASE_STATUS_GRANTED, 0x0102030405060708, 0x11223344)
    );
    // Rejection frame: status 0x00, expires_at MUST be 0.
    let rejected = encode_lease_granted(LEASE_STATUS_REJECTED, 7, 0);
    assert_eq!(rejected[1], 0x00);
    assert_eq!(
        decode_lease_granted(&rejected[1..]).unwrap(),
        (LEASE_STATUS_REJECTED, 7, 0)
    );
    // Malformed: unknown status byte, nonzero expires_at on rejection,
    // wrong lengths — all typed rejections (fail closed).
    let mut bad_status = granted[1..].to_vec();
    bad_status[0] = 0x02;
    assert!(decode_lease_granted(&bad_status).is_err());
    let mut rejected_nonzero = rejected[1..].to_vec();
    rejected_nonzero[16] = 1;
    assert!(decode_lease_granted(&rejected_nonzero).is_err());
    assert!(decode_lease_granted(&granted[1..17]).is_err());
    let mut granted_long = granted[1..].to_vec();
    granted_long.push(0);
    assert!(decode_lease_granted(&granted_long).is_err());
}

#[test]
fn protocol_hello_decode_roundtrip() {
    let frame = encode_protocol_hello();
    assert_eq!(decode_protocol_hello(&frame).unwrap(), PROTOCOL_VERSION);
    let legacy_frame = encode_legacy_full_window_protocol_hello();
    assert_eq!(
        decode_protocol_hello(&legacy_frame).unwrap(),
        LEGACY_FULL_WINDOW_PROTOCOL_VERSION
    );
    // A future-version peer's hello must still DECODE (the caller
    // compares versions and closes) — decode returns the raw byte.
    assert_eq!(decode_protocol_hello(&[TAG_PROTOCOL_HELLO, 7]).unwrap(), 7);
}

#[test]
fn protocol_hello_decode_rejects_malformed_frames() {
    // (case_name, frame)
    let cases: &[(&str, &[u8])] = &[
        ("empty", &[]),
        ("tag_only", &[TAG_PROTOCOL_HELLO]),
        ("trailing_bytes", &[TAG_PROTOCOL_HELLO, PROTOCOL_VERSION, 0]),
        ("wrong_tag", &[TAG_VERSION_VECTOR, PROTOCOL_VERSION]),
    ];
    for (case_name, frame) in cases {
        assert_matches!(
            decode_protocol_hello(frame),
            Err(TransportError::InvalidPayload(_)),
            "case {case_name}: expected InvalidPayload"
        );
    }
}

#[test]
fn window_sync_roundtrip() {
    let key = "2026-02";
    let msg = b"test payload";
    let encoded = encode_window_sync(key, window_sub_tags::UPDATE, msg)
        .into_result()
        .unwrap();
    assert_eq!(encoded[0], TAG_WINDOW_SYNC);
    let (dk, sub, dm) = decode_window_sync(&encoded[1..]).unwrap();
    assert_eq!(dk, key);
    assert_eq!(sub, window_sub_tags::UPDATE);
    assert_eq!(dm, msg);
}

#[test]
fn bulk_transfer_roundtrip() {
    let key = "2025-11";
    let data = vec![1, 2, 3];
    let encoded = encode_bulk_transfer(key, &data).into_result().unwrap();
    assert_eq!(encoded[0], TAG_BULK_TRANSFER);
    let (dk, dd) = decode_bulk_transfer(&encoded[1..]).unwrap();
    assert_eq!(dk, key);
    assert_eq!(dd, &data[..]);
}

#[test]
fn bulk_transfer_done_roundtrip() {
    let key = "2025-09";
    let state = vec![10, 20];
    let encoded = encode_bulk_transfer_done(key, &state)
        .into_result()
        .unwrap();
    assert_eq!(encoded[0], TAG_BULK_TRANSFER_DONE);
    let (dk, ds) = decode_bulk_transfer_done(&encoded[1..]).unwrap();
    assert_eq!(dk, key);
    assert_eq!(ds, &state[..]);
}

#[test]
fn bulk_transfer_done_empty_state() {
    let encoded = encode_bulk_transfer_done("2025-08", &[])
        .into_result()
        .unwrap();
    let (k, s) = decode_bulk_transfer_done(&encoded[1..]).unwrap();
    assert_eq!(k, "2025-08");
    assert!(s.is_empty());
}

#[test]
fn window_sync_encoder_rejects_hostile_keys_without_panicking() {
    for key in ["", "2026-003", "window", "2026-0x"] {
        assert_matches!(
            encode_window_sync(key, window_sub_tags::UPDATE, b"payload").into_result(),
            Err(TransportError::InvalidWindowKey),
            "key {key:?} should return InvalidWindowKey"
        );
    }
}

#[test]
fn bulk_transfer_encoder_rejects_hostile_keys_without_panicking() {
    for key in ["", "2026-003", "window", "2026-0x"] {
        assert_matches!(
            encode_bulk_transfer(key, b"zstd").into_result(),
            Err(TransportError::InvalidWindowKey),
            "key {key:?} should return InvalidWindowKey"
        );
    }
}

#[test]
fn bulk_transfer_done_encoders_reject_hostile_keys_without_panicking() {
    for key in ["", "2026-003", "window", "2026-0x"] {
        assert_matches!(
            encode_bulk_transfer_done(key, b"state").into_result(),
            Err(TransportError::InvalidWindowKey),
            "key {key:?} should return InvalidWindowKey"
        );
        assert_matches!(
            encode_bulk_transfer_done_checked(key, b"state"),
            Err(TransportError::InvalidWindowKey),
            "key {key:?} should return InvalidWindowKey"
        );
    }
}

#[cfg(target_pointer_width = "64")]
#[test]
fn bulk_transfer_done_checked_encoder_rejects_u32_overflow_len() {
    let err = checked_bulk_transfer_done_state_len(u32::MAX as usize + 1).unwrap_err();

    assert_matches!(
        err,
        TransportError::InvalidPayload("BulkTransferDone state too large")
    );
}

#[test]
fn bulk_transfer_done_capacity_rejects_usize_overflow() {
    let err = checked_bulk_transfer_done_capacity(MAX_WINDOW_KEY_LEN, usize::MAX).unwrap_err();

    assert_matches!(
        err,
        TransportError::FrameTooLarge { size, max }
            if size == usize::MAX && max == MAX_ENCODED_FRAME_BYTES
    );
}

#[test]
fn window_sync_encoder_rejects_oversized_payload_without_panicking() {
    let payload = vec![0u8; MAX_ENCODED_FRAME_BYTES];

    assert_matches!(
        encode_window_sync("2026-02", window_sub_tags::UPDATE, &payload).into_result(),
        Err(TransportError::FrameTooLarge { size, max })
            if size == MAX_ENCODED_FRAME_BYTES + 10 && max == MAX_ENCODED_FRAME_BYTES
    );
}

#[test]
fn bulk_transfer_encoder_rejects_oversized_payload_without_panicking() {
    let payload = vec![0u8; MAX_ENCODED_FRAME_BYTES];

    assert_matches!(
        encode_bulk_transfer("2026-02", &payload).into_result(),
        Err(TransportError::FrameTooLarge { size, max })
            if size == MAX_ENCODED_FRAME_BYTES + 9 && max == MAX_ENCODED_FRAME_BYTES
    );
}

#[test]
fn bulk_transfer_done_encoder_rejects_oversized_payload_without_panicking() {
    let state = vec![0u8; MAX_ENCODED_FRAME_BYTES];

    assert_matches!(
        encode_bulk_transfer_done("2026-02", &state).into_result(),
        Err(TransportError::FrameTooLarge { size, max })
            if size == MAX_ENCODED_FRAME_BYTES + 13 && max == MAX_ENCODED_FRAME_BYTES
    );
}

#[test]
fn encoded_frame_len_rejects_usize_overflow() {
    assert_matches!(
        checked_encoded_frame_len(MAX_WINDOW_KEY_LEN, usize::MAX),
        Err(TransportError::FrameTooLarge { size, max })
            if size == usize::MAX && max == MAX_ENCODED_FRAME_BYTES
    );
}

#[test]
fn bulk_transfer_done_rejects_trailing_bytes() {
    let state = vec![10, 20];
    let mut encoded = encode_bulk_transfer_done("2025-09", &state);
    encoded.push(30);

    assert_matches!(
        decode_bulk_transfer_done(&encoded[1..]),
        Err(TransportError::InvalidPayload("state has trailing bytes"))
    );
}

#[test]
fn bulk_transfer_done_rejects_truncated_state() {
    let state = vec![10, 20];
    let mut encoded = encode_bulk_transfer_done("2025-09", &state);
    encoded.pop();

    assert_matches!(
        decode_bulk_transfer_done(&encoded[1..]),
        Err(TransportError::InvalidPayload("state truncated"))
    );
}

#[test]
fn reject_invalid_key_len() {
    assert!(decode_window_sync(&[0, 0]).is_err()); // key_len = 0
    let mut d = vec![8];
    d.extend_from_slice(b"12345678");
    d.push(0); // sub_tag
    assert!(decode_window_sync(&d).is_err()); // key_len = 8
}

#[test]
fn decoders_reject_invalid_calendar_window_keys() {
    // Every wire decoder must reject window keys that fail
    // parse_window_key_str — both calendar-OOB (2026-13) and pre-epoch
    // (1969-12). Each decoder has its own trailing payload shape, so we
    // build a payload tail per decoder.
    type Decoder = fn(&[u8]) -> Result<(), TransportError>;

    let window_sync_decoder: Decoder = |data| decode_window_sync(data).map(|_| ());
    let bulk_transfer_decoder: Decoder = |data| decode_bulk_transfer(data).map(|_| ());
    let bulk_done_decoder: Decoder = |data| decode_bulk_transfer_done(data).map(|_| ());

    let cases: &[(&str, Decoder, &[u8])] = &[
        // (case_name, decoder, payload_tail_after_window_key)
        (
            "decode_window_sync_calendar_oob",
            window_sync_decoder,
            &[window_sub_tags::UPDATE],
        ),
        (
            "decode_window_sync_pre_epoch",
            window_sync_decoder,
            &[window_sub_tags::UPDATE],
        ),
        (
            "decode_bulk_transfer_calendar_oob",
            bulk_transfer_decoder,
            &[1, 2, 3],
        ),
        (
            "decode_bulk_transfer_pre_epoch",
            bulk_transfer_decoder,
            &[1, 2, 3],
        ),
        (
            "decode_bulk_transfer_done_calendar_oob",
            bulk_done_decoder,
            &[0, 0, 0, 0],
        ),
        (
            "decode_bulk_transfer_done_pre_epoch",
            bulk_done_decoder,
            &[0, 0, 0, 0],
        ),
    ];

    let invalid_keys: &[&[u8]] = &[b"2026-13", b"1969-12"];

    for ((case_name, decoder, tail), invalid_key) in cases
        .iter()
        .zip(invalid_keys.iter().cycle().take(cases.len()))
    {
        let mut data = vec![invalid_key.len() as u8];
        data.extend_from_slice(invalid_key);
        data.extend_from_slice(tail);

        assert_matches!(
            decoder(&data),
            Err(TransportError::InvalidWindowKey),
            "case {case_name}: expected InvalidWindowKey for key {:?}",
            std::str::from_utf8(invalid_key).unwrap_or("<bytes>")
        );
    }
}
