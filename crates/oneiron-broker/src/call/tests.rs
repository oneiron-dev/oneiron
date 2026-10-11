//! The checks both sides run on a call (ARCH-0069 `#broker-design`): the
//! digest binds the exact request, and the origin is one exact https origin.

use super::CallHeader;
use crate::{Refusal, Shape, request_digest};

const BODY: &[u8] = br#"{"model":"gpt-x","messages":[]}"#;

fn call(origin: &str) -> CallHeader {
    CallHeader::new(
        "lease-1".to_owned(),
        Shape::OpenAiChat,
        origin.to_owned(),
        "/v1/chat/completions".to_owned(),
        vec![("content-type".to_owned(), "application/json".to_owned())],
        "gpt-x".to_owned(),
        BODY,
    )
}

#[test]
fn the_digest_covers_method_path_headers_and_body_but_not_auth_or_order() {
    let headers = vec![
        ("content-type".to_owned(), "application/json".to_owned()),
        ("x-trace".to_owned(), "1".to_owned()),
    ];
    let base = request_digest("POST", "/v1/chat/completions", &headers, BODY);
    let mut reordered = headers.clone();
    reordered.reverse();
    reordered.push(("Authorization".to_owned(), "Bearer anything".to_owned()));
    assert_eq!(
        request_digest("POST", "/v1/chat/completions", &reordered, BODY),
        base
    );
    let mut other_header = headers.clone();
    other_header[1].1 = "2".to_owned();
    for changed in [
        request_digest("PUT", "/v1/chat/completions", &headers, BODY),
        request_digest("POST", "/api/v1/chat/completions", &headers, BODY),
        request_digest("POST", "/v1/chat/completions", &other_header, BODY),
        request_digest(
            "POST",
            "/v1/chat/completions",
            &headers,
            br#"{"model":"gpt-y","messages":[]}"#,
        ),
    ] {
        assert_ne!(changed, base);
    }
}

#[test]
fn a_call_passes_only_for_its_own_bytes() {
    let call = call("https://api.example.test");
    assert!(call.check(BODY).is_ok());
    assert_eq!(
        call.check(br#"{"model":"gpt-x","messages":[{"role":"user","content":"more"}]}"#),
        Err(Refusal::Digest)
    );
    assert_eq!(
        call.check(br#"{"model":"gpt-y","messages":[]}"#),
        Err(Refusal::WireModel)
    );
    let mut auth = call.clone();
    auth.headers.push(("x-api-key".to_owned(), "k".to_owned()));
    assert_eq!(auth.check(BODY), Err(Refusal::Header));
    let mut encoded = call;
    encoded
        .headers
        .push(("accept-encoding".to_owned(), "gzip".to_owned()));
    assert_eq!(encoded.check(BODY), Err(Refusal::Header));
}

#[test]
fn the_origin_is_one_exact_https_origin() {
    assert!(call("https://127.0.0.1:8443").check(BODY).is_ok());
    for origin in [
        "http://api.example.test",
        "https://api.example.test/",
        "https://api.example.test/v1",
        "https://user@api.example.test",
        "https://API.example.test",
        "https://api.example.test:443",
        "https://api.example.test?x=1",
    ] {
        assert_eq!(call(origin).check(BODY), Err(Refusal::Origin), "{origin}");
    }
}

#[test]
fn a_call_too_large_to_frame_is_refused_by_the_check() {
    // The broker's frame reader would refuse these; the check both sides run
    // refuses them first, by name.
    let call = call("https://api.example.test");
    assert_eq!(
        call.check(&vec![b' '; crate::MAX_BODY + 1]),
        Err(Refusal::Body)
    );
    let mut long = call;
    long.path = format!("/v1/{}", "a".repeat(crate::frame::MAX_HEADER));
    assert_eq!(long.check(BODY), Err(Refusal::Frame));
}
