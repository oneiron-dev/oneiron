//! Decoder checks over provider-shaped replies.
use serde_json::json;

/// F14 H122 (Astra, round 7): a Gemini part with text beside a function call
/// decoded as its text alone, a `Stop` the policy classifier took for a
/// finished, tool-free answer: an Allow. A part holds one piece of data, so a
/// second one beside the text fails the decode, buffered and streamed. A text
/// part with its thought markers and a lone function call still decode.
#[test]
fn a_function_call_beside_text_never_decodes_as_a_finished_answer() {
    let allow = "{\"violation\":0,\"policy_category\":null}";
    let reply = |part: serde_json::Value| {
        json!({ "candidates": [{
            "content": { "role": "model", "parts": [part] },
            "finishReason": "STOP",
        }] })
    };
    for part in [
        json!({ "text": allow, "functionCall": { "name": "check_policy", "args": {} } }),
        json!({ "text": allow, "functionCall": { "args": {} } }),
        json!({ "text": allow, "executableCode": { "language": "PYTHON", "code": "print(1)" } }),
    ] {
        assert!(
            super::wire::parse_response(reply(part.clone())).is_err(),
            "H122: {part} decoded as a finished, tool-free answer"
        );
        assert!(
            super::stream::GeminiAccumulator::default()
                .push(reply(part.clone()))
                .is_err(),
            "H122: a streamed {part} finished as a tool-free answer"
        );
    }

    // The controls.
    let answer = super::wire::parse_response(reply(
        json!({ "text": allow, "thoughtSignature": "signature" }),
    ))
    .expect("a text part decodes");
    assert_eq!(answer.finish_reason, oneiron::FinishReason::Stop);
    let called = super::wire::parse_response(reply(
        json!({ "functionCall": { "name": "check_policy", "args": {} } }),
    ))
    .expect("a lone function call decodes");
    assert_eq!(called.finish_reason, oneiron::FinishReason::ToolCalls);
}
