use oneiron::FinishReason;
use serde_json::json;

use super::{AnthropicMessagesStreamAccumulator, parse_anthropic_messages_response};

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

/// F14 H122 (round 8): the buffered decoder skipped a content block it could
/// not read, so a server tool request beside the text decoded as a finished,
/// tool-free answer: an Allow. Any block kind but text, reasoning and a client
/// tool call now fails the decode, as the streamed decoder's start event
/// already does. Redacted reasoning beside the text still decodes.
#[test]
fn an_unreadable_block_never_decodes_as_a_finished_answer() {
    let allow = json!({ "type": "text", "text": "{\"violation\":0}" });
    for block in [
        json!({ "type": "server_tool_use", "id": "call-1", "name": "web_search", "input": {} }),
        json!({ "type": "mcp_tool_use", "id": "call-1", "name": "check_policy", "input": {} }),
        json!({ "id": "call-1", "name": "check_policy", "input": {} }),
    ] {
        let body = json!({ "content": [allow.clone(), block], "stop_reason": "end_turn" });
        assert!(
            parse_anthropic_messages_response(&body).is_err(),
            "H122: {body} decoded as a finished, tool-free answer"
        );
    }
    let body = json!({
        "content": [{ "type": "redacted_thinking", "data": "opaque" }, allow],
        "stop_reason": "end_turn",
    });
    let answer = parse_anthropic_messages_response(&body).expect("redacted reasoning decodes");
    assert_eq!(answer.finish_reason, FinishReason::Stop);
}

/// F14 H122 (Astra, round 9): the stream read only usage from the opening
/// message, so a tool block it carried vanished and the text that followed
/// finished as a tool-free answer. Blocks arrive as their own events; an
/// opening message that carries any, or is no object, fails the stream. The
/// ordinary opening with empty content still streams.
#[test]
fn an_opening_message_with_blocks_never_finishes_as_a_tool_free_answer() {
    let tool = json!({ "type": "tool_use", "id": "call-1", "name": "check_policy", "input": {} });
    for message in [
        json!({ "role": "assistant", "content": [tool], "usage": { "input_tokens": 3 } }),
        json!({ "role": "assistant", "content": tool }),
        json!([{ "content": [tool] }]),
    ] {
        let mut stream = AnthropicMessagesStreamAccumulator::new();
        assert!(
            stream
                .push_event(json!({ "type": "message_start", "message": message }))
                .is_err(),
            "H122: an opening {message} streamed on"
        );
    }
    let mut stream = AnthropicMessagesStreamAccumulator::new();
    stream
        .push_event(json!({ "type": "message_start", "message": {
            "role": "assistant", "content": [], "usage": { "input_tokens": 3 } } }))
        .expect("the ordinary opening streams");
}
