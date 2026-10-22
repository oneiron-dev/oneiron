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

/// F12 (H90): a tool or structured-output control that arrives through raw
/// params or provider options needs the capability its typed field would.
/// The typed checks read only the typed fields, so a model without tool
/// calling or JSON output used to get `tools`, `tool_choice` or
/// `output_config.format` on the wire.
#[test]
fn a_raw_tool_or_format_control_needs_the_capability_its_typed_field_would() {
    use oneiron::llm::{CallClass, CallEnvelope, CallPurpose, ModelTierRef, TierPrecedence};
    use oneiron::{
        ContentPart, FatalLlmError, LlmCapability, LlmCatalogEntry, LlmError, LlmMessage,
        LlmMessageRole, LlmRequest, ModelId, ModelLocality, ResponseFormat,
    };
    use std::collections::BTreeMap;

    const MODEL: &str = "fake/teacher@v1";
    let config = |capabilities: Vec<LlmCapability>| {
        super::AnthropicMessagesConfig::from_catalog([LlmCatalogEntry {
            model: ModelId::new(MODEL).expect("model"),
            display_name: "teacher".to_owned(),
            locality: ModelLocality::ThirdParty,
            context_window_tokens: 8_192,
            max_output_tokens: None,
            cost: None,
            capabilities,
            metadata: BTreeMap::new(),
        }])
    };
    let request = || {
        let purpose = CallPurpose::Other {
            name: "teacher".to_owned(),
        };
        LlmRequest {
            model: ModelId::new(MODEL).expect("model"),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(&purpose, ModelTierRef("teacher".to_owned())),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Text,
                locality: ModelLocality::ThirdParty,
            },
            messages: vec![LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: "label this pair".to_owned(),
                }],
            }],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
            host_segments: None,
        }
    };
    let bare = config(vec![LlmCapability::Streaming]);
    for (key, value, capability) in [
        (
            "tools",
            json!([{ "name": "run", "input_schema": { "type": "object" } }]),
            LlmCapability::ToolCalling,
        ),
        (
            "tool_choice",
            json!({ "type": "any" }),
            LlmCapability::ToolCalling,
        ),
        (
            "mcp_servers",
            json!([{ "type": "url", "url": "https://tools.example.test", "name": "remote" }]),
            LlmCapability::ToolCalling,
        ),
        (
            "output_format",
            json!({ "type": "json_schema", "schema": { "type": "object" } }),
            LlmCapability::JsonResponse,
        ),
        (
            "output_config",
            json!({ "format": { "type": "json_schema", "schema": { "type": "object" } } }),
            LlmCapability::JsonResponse,
        ),
    ] {
        for via_options in [false, true] {
            let mut call = request();
            if via_options {
                let mut options = serde_json::Map::new();
                options.insert(key.to_owned(), value.clone());
                call.provider_options
                    .insert("anthropic".to_owned(), serde_json::Value::Object(options));
            } else {
                call.params.insert(key.to_owned(), value.clone());
            }
            for stream in [false, true] {
                match super::build_anthropic_messages_request(&bare, &call, stream) {
                    Err(LlmError::Fatal(FatalLlmError::Unsupported(refused))) => {
                        assert_eq!(refused.capability, capability, "{key}");
                    }
                    other => panic!(
                        "raw {key} (options: {via_options}, stream: {stream}) must be refused: {other:?}"
                    ),
                }
            }
            let able = config(vec![LlmCapability::Streaming, capability.clone()]);
            let body = super::build_anthropic_messages_request(&able, &call, false)
                .expect("a capable model takes the raw control")
                .body;
            assert_eq!(body[key], value, "{body}");
        }
    }

    let mut call = request();
    call.params.insert("temperature".to_owned(), json!(0.2));
    call.params
        .insert("output_config".to_owned(), json!({ "effort": "low" }));
    let body = super::build_anthropic_messages_request(&bare, &call, false)
        .expect("a sampling field and an effort-only output_config need no capability")
        .body;
    assert_eq!(body["temperature"], 0.2, "{body}");
}
