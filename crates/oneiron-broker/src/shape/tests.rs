//! The selector parser's refusals, as `#door-reads-model` and the broker
//! design list them: the parser reads the exact bytes that will be sent.

use super::Shape;
use crate::Refusal;

#[test]
fn the_selector_is_the_top_level_model_string_of_the_exact_bytes() {
    let body = br#"{"messages":[{"role":"user","content":"hi","model":"inner"}],"model":"gpt-x"}"#;
    assert_eq!(
        Shape::OpenAiChat.read_selector(body),
        Ok("gpt-x".to_owned())
    );
    assert_eq!(
        Shape::AnthropicMessages.read_selector(br#"{"model":"claude-x","max_tokens":5}"#),
        Ok("claude-x".to_owned())
    );
}

#[test]
fn every_way_to_name_another_model_or_route_is_refused() {
    let cases: [(&[u8], Refusal); 10] = [
        (br#"{"messages":[]}"#, Refusal::SelectorMissing),
        // A plain decode keeps the last of two keys; the counter sees both.
        (
            br#"{"model":"cheap","model":"dear"}"#,
            Refusal::SelectorRepeated,
        ),
        // An escaped spelling is still `model`.
        (
            br#"{"model":"cheap","mod\u0065l":"dear"}"#,
            Refusal::SelectorRepeated,
        ),
        (br#"{"model":["cheap","dear"]}"#, Refusal::SelectorNotString),
        (
            br#"{"model":"cheap","models":["dear"]}"#,
            Refusal::RouteOverride,
        ),
        (
            br#"{"model":"cheap","route":"fallback"}"#,
            Refusal::RouteOverride,
        ),
        (
            br#"{"model":"cheap","provider":{"order":["x"]}}"#,
            Refusal::RouteOverride,
        ),
        (br#"[{"model":"cheap"}]"#, Refusal::Body),
        (br#"{"model":"cheap"} {"model":"dear"}"#, Refusal::Body),
        (b"{\"model\":\"cheap\"", Refusal::Body),
    ];
    for (body, refusal) in cases {
        assert_eq!(
            Shape::OpenAiChat.read_selector(body),
            Err(refusal),
            "{}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn only_the_plain_endpoint_path_is_accepted() {
    for path in ["/v1/chat/completions", "/api/v1/chat/completions"] {
        assert_eq!(Shape::OpenAiChat.check_path(path), Ok(()), "{path}");
    }
    for path in [
        "/v1/messages",
        "/v1/chat/completions?model=dear",
        "/v1/chat/completions#x",
        "/x/../v1/chat/completions",
        "//evil.example/v1/chat/completions",
        "/v1/chat/%63ompletions",
        "v1/chat/completions",
    ] {
        assert_eq!(
            Shape::OpenAiChat.check_path(path),
            Err(Refusal::Path),
            "{path}"
        );
    }
    assert_eq!(Shape::AnthropicMessages.check_path("/v1/messages"), Ok(()));
}
