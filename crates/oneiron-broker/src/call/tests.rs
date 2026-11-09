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
