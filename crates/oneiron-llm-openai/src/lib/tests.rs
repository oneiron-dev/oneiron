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
