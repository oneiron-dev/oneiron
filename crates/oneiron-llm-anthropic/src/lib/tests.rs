use super::*;

use oneiron::{
    CallClass, CallEnvelope, CallPurpose, DeterministicFallback, ModelLocality, ModelTierRef,
    TierPrecedence,
};

#[test]
fn status_code_table_maps_to_typed_errors() {
    let headers = BTreeMap::from([("retry-after".to_owned(), "9".to_owned())]);
    let body = json!({ "error": { "type": "rate_limit_error" } });

    assert!(matches!(
        classify_anthropic_status(429, &headers, &body),
        LlmError::Retryable(RetryableLlmError::RateLimited {
            retry_after: Some(9)
        })
    ));
    assert!(matches!(
        classify_anthropic_status(
            529,
            &BTreeMap::new(),
            &json!({ "error": { "type": "overloaded_error" } })
        ),
        LlmError::Retryable(RetryableLlmError::ServerError)
    ));
    assert!(matches!(
        classify_anthropic_status(408, &BTreeMap::new(), &json!({})),
        LlmError::Retryable(RetryableLlmError::Timeout)
    ));
    assert!(matches!(
        classify_anthropic_status(
            401,
            &BTreeMap::new(),
            &json!({ "error": { "type": "authentication_error" } })
        ),
        LlmError::Fatal(FatalLlmError::Auth)
    ));
    assert!(matches!(
        classify_anthropic_status(
            400,
            &BTreeMap::new(),
            &json!({ "error": { "type": "invalid_request_error" } })
        ),
        LlmError::Fatal(FatalLlmError::InvalidRequest)
    ));
    assert!(matches!(
        classify_anthropic_status(
            400,
            &BTreeMap::new(),
            &json!({ "error": { "type": "content_filter_error" } })
        ),
        LlmError::Fatal(FatalLlmError::ContentFiltered)
    ));
}

#[test]
fn unsupported_capability_is_typed() {
    let catalog = catalog_with([LlmCapability::JsonResponse]);
    let config = AnthropicMessagesConfig::new(catalog);
    let mut request = sample_request();
    request.tools = vec![LlmToolSpec {
        name: "route".to_owned(),
        description: "Route a call".to_owned(),
        input_schema: json!({ "type": "object" }),
    }];

    let error = build_anthropic_messages_request(&config, &request, false).unwrap_err();
    assert!(matches!(
        error,
        LlmError::Fatal(FatalLlmError::Unsupported(UnsupportedCapability {
            capability: LlmCapability::ToolCalling,
            ..
        }))
    ));
}

#[test]
fn json_response_maps_to_native_output_config_format() {
    let catalog = catalog_with([LlmCapability::JsonResponse]);
    let config = AnthropicMessagesConfig::new(catalog);
    let request = sample_request();

    let wire = build_anthropic_messages_request(&config, &request, false).unwrap();

    assert_eq!(
        wire.body.get("output_config"),
        Some(&json!({
            "format": {
                "type": "json_schema",
                "schema": { "type": "object" },
            }
        }))
    );
    assert_eq!(wire.body.get("response_format"), None);
}

#[test]
fn json_response_merges_into_caller_output_config() {
    let catalog = catalog_with([LlmCapability::JsonResponse]);
    let config = AnthropicMessagesConfig::new(catalog);
    let mut request = sample_request();
    request
        .params
        .insert("output_config".to_owned(), json!({ "effort": "high" }));

    let wire = build_anthropic_messages_request(&config, &request, false).unwrap();

    assert_eq!(
        wire.body.get("output_config"),
        Some(&json!({
            "effort": "high",
            "format": {
                "type": "json_schema",
                "schema": { "type": "object" },
            }
        }))
    );
    assert_eq!(wire.body.get("response_format"), None);
}

#[test]
fn caller_response_format_param_is_stripped_from_wire() {
    let catalog = catalog_with([LlmCapability::JsonResponse]);
    let config = AnthropicMessagesConfig::new(catalog);
    let mut request = sample_request();
    request.envelope.response_format = ResponseFormat::Text;
    request.params.insert(
        "response_format".to_owned(),
        json!({ "type": "json_schema", "schema": { "type": "object" } }),
    );

    let wire = build_anthropic_messages_request(&config, &request, false).unwrap();

    assert_eq!(wire.body.get("response_format"), None);
}

#[test]
fn non_object_output_config_with_json_response_is_invalid_request() {
    let catalog = catalog_with([LlmCapability::JsonResponse]);
    let config = AnthropicMessagesConfig::new(catalog);
    let mut request = sample_request();
    request
        .params
        .insert("output_config".to_owned(), json!("not-an-object"));

    let error = build_anthropic_messages_request(&config, &request, false).unwrap_err();
    assert!(matches!(
        error,
        LlmError::Fatal(FatalLlmError::InvalidRequest)
    ));
}

#[test]
fn provider_options_parse_typed_fields_and_preserve_raw_escape_hatch() {
    let options = AnthropicProviderOptions::from_namespaced_value(&json!({
        "thinking": { "type": "enabled", "budget_tokens": 1024 },
        "metadata": { "user_id": "tenant-a" },
        "vendor_extension": { "mode": "strict" }
    }))
    .unwrap();

    assert_eq!(
        options
            .thinking
            .as_ref()
            .map(|thinking| thinking.kind.as_str()),
        Some("enabled")
    );
    assert_eq!(options.metadata, Some(json!({ "user_id": "tenant-a" })));
    assert_eq!(
        options.raw.get("vendor_extension"),
        Some(&json!({ "mode": "strict" }))
    );

    let wire = options.to_wire_fields();
    assert_eq!(
        wire.get("metadata"),
        Some(&json!({ "user_id": "tenant-a" }))
    );
    assert_eq!(
        wire.get("vendor_extension"),
        Some(&json!({ "mode": "strict" }))
    );
}

#[test]
fn abort_retains_partial_text_and_settles_usage() {
    let mut accumulator = AnthropicMessagesStreamAccumulator::new();
    accumulator
        .push_event(json!({
            "type": "content_block_delta",
            "delta": { "type": "text_delta", "text": "help" }
        }))
        .unwrap();

    let usage = LlmUsage {
        input: LlmInputUsage {
            total: 7,
            cache_read: 2,
            cache_write: 1,
        },
        output: LlmOutputUsage {
            total: 3,
            text: 3,
            reasoning: 0,
        },
        raw_provider: json!({ "input_tokens": 7, "output_tokens": 3 }),
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
        model: ModelId::new("anthropic/claude-sonnet@2026-07-02").unwrap(),
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
        model: ModelId::new("anthropic/claude-sonnet@2026-07-02").unwrap(),
        display_name: "Claude Sonnet".to_owned(),
        locality: ModelLocality::ThirdParty,
        context_window_tokens: 200_000,
        max_output_tokens: Some(8_192),
        cost: None,
        capabilities: capabilities.into_iter().collect(),
        metadata: BTreeMap::new(),
    }
}
