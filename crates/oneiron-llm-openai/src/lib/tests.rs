//! Unit tests for wire mapping, classification, options round-trip, and accumulator abort behavior.

use super::*;

use oneiron::{
    CallClass, CallEnvelope, CallPurpose, DeterministicFallback, ModelLocality, ModelTierRef,
    TierPrecedence,
};

#[test]
fn status_code_table_maps_to_typed_errors() {
    let headers = BTreeMap::from([("retry-after".to_owned(), "12".to_owned())]);
    let body = json!({ "error": { "message": "rate limit" } });

    assert!(matches!(
        classify_openai_status(429, &headers, &body),
        LlmError::Retryable(RetryableLlmError::RateLimited {
            retry_after: Some(12)
        })
    ));
    assert!(matches!(
        classify_openai_status(500, &BTreeMap::new(), &body),
        LlmError::Retryable(RetryableLlmError::ServerError)
    ));
    assert!(matches!(
        classify_openai_status(408, &BTreeMap::new(), &body),
        LlmError::Retryable(RetryableLlmError::Timeout)
    ));
    assert!(matches!(
        classify_openai_status(401, &BTreeMap::new(), &body),
        LlmError::Fatal(FatalLlmError::Auth)
    ));
    assert!(matches!(
        classify_openai_status(400, &BTreeMap::new(), &body),
        LlmError::Fatal(FatalLlmError::InvalidRequest)
    ));
    assert!(matches!(
        classify_openai_status(
            400,
            &BTreeMap::new(),
            &json!({ "error": { "code": "content_filter" } })
        ),
        LlmError::Fatal(FatalLlmError::ContentFiltered)
    ));
}

#[test]
fn unsupported_capability_is_typed() {
    let catalog = catalog_with([LlmCapability::JsonResponse]);
    let config = OpenAiCompatConfig::new(catalog);
    let mut request = sample_request();
    request.tools = vec![LlmToolSpec {
        name: "route".to_owned(),
        description: "Route a call".to_owned(),
        input_schema: json!({ "type": "object" }),
    }];

    let error = build_openai_chat_request(&config, &request, false).unwrap_err();
    assert!(matches!(
        error,
        LlmError::Fatal(FatalLlmError::Unsupported(UnsupportedCapability {
            capability: LlmCapability::ToolCalling,
            ..
        }))
    ));
}

#[test]
fn provider_options_parse_typed_fields_and_preserve_raw_escape_hatch() {
    let options = OpenAiProviderOptions::from_namespaced_value(&json!({
        "parallel_tool_calls": false,
        "reasoning": { "effort": "medium", "summary": "auto" },
        "vendor_extension": { "mode": "strict" }
    }))
    .unwrap();

    assert_eq!(options.parallel_tool_calls, Some(false));
    assert_eq!(
        options
            .reasoning
            .as_ref()
            .and_then(|reasoning| reasoning.effort.as_deref()),
        Some("medium")
    );
    assert_eq!(
        options.raw.get("vendor_extension"),
        Some(&json!({ "mode": "strict" }))
    );

    let wire = options.to_wire_fields();
    assert_eq!(wire.get("parallel_tool_calls"), Some(&json!(false)));
    assert_eq!(
        wire.get("vendor_extension"),
        Some(&json!({ "mode": "strict" }))
    );
}

#[test]
fn abort_retains_partial_text_and_settles_usage() {
    let mut accumulator = OpenAiCompatStreamAccumulator::new();
    let events = accumulator
        .push_chunk(json!({
            "choices": [{
                "delta": { "content": "help" },
                "finish_reason": null
            }]
        }))
        .unwrap();
    assert!(matches!(
        events.first(),
        Some(LlmStreamEvent::TextStart { .. })
    ));

    let usage = LlmUsage {
        input: LlmInputUsage {
            total: 7,
            cache_read: 2,
            cache_write: 0,
        },
        output: LlmOutputUsage {
            total: 3,
            text: 3,
            reasoning: 0,
        },
        raw_provider: json!({ "prompt_tokens": 7, "completion_tokens": 3 }),
    };
    let abort_events = accumulator.abort_with_usage(usage.clone());
    let done = abort_events
        .iter()
        .find_map(|event| match event {
            LlmStreamEvent::Done {
                message,
                usage,
                finish_reason,
            } => Some((message, usage, finish_reason)),
            _ => None,
        })
        .expect("abort should settle with Done");

    assert_eq!(
        done.0.content,
        vec![ContentPart::Text {
            text: "help".to_owned()
        }]
    );
    assert_eq!(*done.1, usage);
    assert_eq!(*done.2, FinishReason::Cancelled);
}

fn sample_request() -> LlmRequest {
    LlmRequest {
        model: ModelId::new("openai/gpt-4.1@2026-07-02").unwrap(),
        envelope: CallEnvelope {
            purpose: CallPurpose::AnswerGen,
            class: CallClass::Durable {
                fallback: DeterministicFallback {
                    name: "fallback".to_owned(),
                    config: None,
                },
            },
            tier: TierPrecedence {
                per_call: None,
                vault_policy: None,
                purpose_default: None,
                global_default: ModelTierRef("standard".to_owned()),
            },
            response_format: ResponseFormat::Json {
                schema: json!({ "type": "object" }),
            },
            locality: ModelLocality::ThirdParty,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: "hello".to_owned(),
            }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    }
}

fn catalog_with(capabilities: impl IntoIterator<Item = LlmCapability>) -> LlmCatalogEntry {
    LlmCatalogEntry {
        model: ModelId::new("openai/gpt-4.1@2026-07-02").unwrap(),
        display_name: "GPT 4.1".to_owned(),
        locality: ModelLocality::ThirdParty,
        context_window_tokens: 1_000_000,
        max_output_tokens: Some(32_000),
        cost: None,
        capabilities: capabilities.into_iter().collect(),
        metadata: BTreeMap::new(),
    }
}

#[test]
fn interleaved_reasoning_and_tools_reconstruct_executable_message() {
    let mut stream = OpenAiCompatStreamAccumulator::new();
    let mut events = stream.push_chunk(json!({"choices":[{"delta":{"reasoning_content":"plan", "content":"look", "tool_calls":[{"index":0,"id":"call-1","function":{"name":"double","arguments":"{\"n\":"}}]}}]})).unwrap();
    events.extend(stream.push_chunk(json!({"choices":[{"delta":{"content":" up", "tool_calls":[{"index":0,"function":{"arguments":"4}"}}]},"finish_reason":"tool_calls"}]})).unwrap());
    events.extend(stream.finish_eof().unwrap());
    assert_eq!(
        &events[..events.len() - 1],
        &[
            LlmStreamEvent::TextStart {
                part_id: "text-0".into()
            },
            LlmStreamEvent::TextDelta {
                part_id: "text-0".into(),
                text: "look".into()
            },
            LlmStreamEvent::ReasoningStart {
                part_id: "reasoning-0".into(),
                signature: None
            },
            LlmStreamEvent::ReasoningDelta {
                part_id: "reasoning-0".into(),
                text: "plan".into()
            },
            LlmStreamEvent::ToolCallStart {
                part_id: "tool-0".into(),
                call_id: "call-1".into(),
                name: "double".into()
            },
            LlmStreamEvent::ToolCallDelta {
                part_id: "tool-0".into(),
                input_fragment: "{\"n\":".into()
            },
            LlmStreamEvent::TextDelta {
                part_id: "text-0".into(),
                text: " up".into()
            },
            LlmStreamEvent::ToolCallDelta {
                part_id: "tool-0".into(),
                input_fragment: "4}".into()
            },
            LlmStreamEvent::TextEnd {
                part_id: "text-0".into()
            },
            LlmStreamEvent::ReasoningEnd {
                part_id: "reasoning-0".into()
            },
            LlmStreamEvent::ToolCallEnd {
                part_id: "tool-0".into(),
                call_id: "call-1".into(),
                name: "double".into(),
                input: json!({"n":4})
            },
        ]
    );
    let LlmStreamEvent::Done { message, .. } = events.last().unwrap() else {
        panic!("missing terminal")
    };
    assert_eq!(
        message.content,
        vec![
            ContentPart::Text {
                text: "look up".into()
            },
            ContentPart::Reasoning {
                text: "plan".into(),
                signature: None
            },
            ContentPart::ToolCall {
                call_id: "call-1".into(),
                name: "double".into(),
                input: json!({"n":4})
            }
        ]
    );
    let ContentPart::ToolCall { name, input, .. } = &message.content[2] else {
        panic!("tool missing")
    };
    let result = match name.as_str() {
        "double" => input["n"].as_i64().unwrap() * 2,
        _ => panic!("unknown tool"),
    };
    assert_eq!(result, 8);
}

#[test]
fn malformed_tool_json_is_rejected_only_at_end_and_cancel_never_executes_it() {
    let mut stream = OpenAiCompatStreamAccumulator::new();
    stream.push_chunk(json!({"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c","function":{"name":"f","arguments":"{"}}]}}]})).unwrap();
    let mut cancelled = stream.clone();
    assert!(matches!(
        stream.push_chunk(json!({"choices":[{"finish_reason":"tool_calls"}],"usage":{}})),
        Err(LlmError::Fatal(FatalLlmError::InvalidRequest))
    ));
    let events = cancelled.abort_with_usage(LlmUsage::zero());
    assert!(
        matches!(&events[0], LlmStreamEvent::Done { message, finish_reason: FinishReason::Cancelled, .. } if message.content.is_empty())
    );
}

#[test]
fn terminal_waits_for_trailing_usage_chunk() {
    let mut stream = OpenAiCompatStreamAccumulator::new();
    let events = stream
        .push_chunk(json!({"choices":[{"delta":{"content":"hi"},"finish_reason":"stop"}]}))
        .unwrap();
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, LlmStreamEvent::Done { .. }))
    );
    let terminal = stream
        .push_chunk(json!({"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3}}))
        .unwrap();
    assert!(
        matches!(terminal.last(),Some(LlmStreamEvent::Done{usage,..})if usage.input.total==7 && usage.output.total==3)
    );
}

#[test]
fn header_only_tool_is_not_silently_lost_at_terminal() {
    let mut stream = OpenAiCompatStreamAccumulator::new();
    stream.push_chunk(json!({"choices":[{"delta":{"content":"working", "tool_calls":[{"index":0,"id":"call","function":{"name":"double"}}]}}]})).unwrap();
    assert!(matches!(
        stream.push_chunk(json!({"choices":[{"finish_reason":"tool_calls"}],"usage":{}})),
        Err(LlmError::Fatal(FatalLlmError::InvalidRequest))
    ));
}

#[test]
fn parallel_tool_fragments_keep_distinct_call_ids_and_inputs() {
    let mut stream = OpenAiCompatStreamAccumulator::new();
    let mut events = stream
        .push_chunk(json!({"choices":[{"delta":{"tool_calls":[
            {"index":0,"id":"a","function":{"name":"double","arguments":"{\"n\":"}},
            {"index":1,"id":"b","function":{"name":"double","arguments":"{\"n\":"}}
        ]}}]}))
        .unwrap();
    events.extend(
        stream
            .push_chunk(json!({"choices":[{"delta":{"tool_calls":[
        {"index":1,"function":{"arguments":"5}"}},
        {"index":0,"function":{"arguments":"4}"}}
    ]},"finish_reason":"tool_calls"}],"usage":{}}))
            .unwrap(),
    );
    for (part, call, value) in [("tool-0", "a", 4), ("tool-1", "b", 5)] {
        let start = events.iter().position(|e| matches!(e, LlmStreamEvent::ToolCallStart { part_id, call_id, .. } if part_id == part && call_id == call)).unwrap();
        let end = events.iter().position(|e| matches!(e, LlmStreamEvent::ToolCallEnd { part_id, call_id, input, .. } if part_id == part && call_id == call && input == &json!({"n": value}))).unwrap();
        assert!(start < end);
        let fragments: String = events[start + 1..end]
            .iter()
            .filter_map(|e| match e {
                LlmStreamEvent::ToolCallDelta {
                    part_id,
                    input_fragment,
                } if part_id == part => Some(input_fragment.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&fragments).unwrap(),
            json!({"n":value})
        );
    }
    let LlmStreamEvent::Done { message, .. } = events.last().unwrap() else {
        panic!("terminal")
    };
    assert_eq!(
        message.content,
        vec![
            ContentPart::ToolCall {
                call_id: "a".into(),
                name: "double".into(),
                input: json!({"n":4})
            },
            ContentPart::ToolCall {
                call_id: "b".into(),
                name: "double".into(),
                input: json!({"n":5})
            },
        ]
    );
}
