use oneiron::FinishReason;
use serde_json::json;

use super::parse_anthropic_messages_response;

/// A reply that names no stop reason is not a finished one. The decoder used
/// to fill in `Stop`, which every caller that demands a finished answer (the
/// policy classifier among them) then read as one.
#[test]
fn a_reply_that_names_no_stop_reason_is_not_a_stop() {
    let content = json!([{ "type": "text", "text": "{\"violation\":0}" }]);
    for body in [
        json!({ "content": content }),
        json!({ "content": content, "stop_reason": null }),
        json!({ "content": content, "stop_reason": 7 }),
    ] {
        let response = parse_anthropic_messages_response(&body).expect("the reply decodes");
        assert_ne!(response.finish_reason, FinishReason::Stop, "{body}");
    }
    let stopped = parse_anthropic_messages_response(
        &json!({ "content": content, "stop_reason": "end_turn" }),
    )
    .expect("the reply decodes");
    assert_eq!(stopped.finish_reason, FinishReason::Stop);
}
