//! Framing/refusal tests only. Real native evidence is recorded separately.

use super::*;

fn frame(ok: bool, request_id: &str, body: &[u8]) -> Vec<u8> {
    let mut data = serde_json::to_vec(&json!({
        "protocol": PROTOCOL, "request_id": request_id, "body_bytes": body.len(),
        "ok": ok, "result": {},
        "error": {"code": "ForcedAlignmentUnavailable"},
    }))
    .expect("fixture header");
    data.push(b'\n');
    data.extend_from_slice(body);
    data
}

#[test]
fn native_refusal_keeps_stage_and_code() {
    let result = parse_reply(
        "transcribe_pack",
        "request",
        false,
        frame(false, "request", b""),
    );
    assert!(matches!(result, Err(AudioError::Host { stage, code })
        if stage == "transcribe_pack" && code == "ForcedAlignmentUnavailable"));
}

#[test]
fn mismatched_and_trailing_response_data_fail_closed() {
    for (stage, success, response) in [
        ("decode", true, frame(true, "other-request", b"")),
        ("decode", false, frame(true, "request", b"")),
        (
            "silero_vad",
            true,
            frame(true, "request", b"unexpected-pcm"),
        ),
        ("decode", true, {
            let mut response = frame(true, "request", b"pcm");
            response.push(1);
            response
        }),
    ] {
        assert!(matches!(parse_reply(stage, "request", success, response),
            Err(AudioError::Host { code, .. }) if code == "InvalidResponse"));
    }
}

#[test]
fn decoded_raw_bytes_are_not_json_samples() {
    let bytes = [0, 128, 255, 127, 0, 0];
    let reply = parse_reply("decode", "request", true, frame(true, "request", &bytes))
        .expect("valid response");
    assert_eq!(reply.body, bytes);
}

#[test]
fn oversized_or_unframed_headers_refuse() {
    for bytes in [vec![b' '; MAX_HEADER + 1], b"{}".to_vec()] {
        assert!(matches!(parse_reply("decode", "request", true, bytes),
            Err(AudioError::Host { code, .. }) if code == "InvalidResponse"));
    }
}
