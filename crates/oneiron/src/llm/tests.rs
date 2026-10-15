use super::*;
use serde_json::json;

#[test]
fn request_hash_is_order_insensitive_but_semantics_sensitive() {
    let request = sample_request();
    let reordered = sample_request_with_reordered_maps();

    assert_eq!(
        request.canonical_hash_hex().unwrap(),
        reordered.canonical_hash_hex().unwrap(),
        "canonical key must ignore JSON object insertion order"
    );

    for (name, mutated) in semantic_mutations(&request) {
        assert_ne!(
            request.canonical_hash_hex().unwrap(),
            mutated.canonical_hash_hex().unwrap(),
            "{name} must affect the canonical key"
        );
    }
}

#[test]
fn call_class_uses_kind_tag_inside_envelope() {
    let envelope = sample_envelope();
    let value = serde_json::to_value(&envelope).unwrap();

    assert_eq!(value["class"]["kind"], "durable");
    assert!(value["class"].get("class").is_none());
}

#[test]
fn rate_limit_error_uses_contract_retry_after_field() {
    let value = serde_json::to_value(RetryableLlmError::RateLimited {
        retry_after: Some(250),
    })
    .unwrap();
    let JsonValue::Object(error) = value else {
        panic!("error should serialize as an object");
    };
    let payload = error.get("RateLimited").expect("rate limited payload");

    assert_eq!(payload["retry_after"], json!(250));
    assert!(payload.get("retry_after_ms").is_none());
}

fn sample_request() -> LlmRequest {
    let mut params = BTreeMap::new();
    params.insert("temperature".to_owned(), json!(0.2));
    params.insert(
        "sampling".to_owned(),
        json!({
            "top_p": 0.8,
            "seed": 7,
        }),
    );

    let mut provider_options = BTreeMap::new();
    provider_options.insert(
        "openai".to_owned(),
        json!({
            "parallel_tool_calls": false,
            "reasoning": {
                "effort": "medium",
                "summary": "auto",
            },
        }),
    );

    LlmRequest {
        model: ModelId::new("openai/gpt-4.1@2026-07-02").unwrap(),
        envelope: sample_envelope(),
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: "You classify memory writes.".to_owned(),
                }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![
                    ContentPart::Text {
                        text: "Classify this claim.".to_owned(),
                    },
                    ContentPart::Image {
                        media_type: "image/png".to_owned(),
                        image: ImageContent::Url {
                            url: "https://example.com/claim.png".to_owned(),
                        },
                    },
                ],
            },
        ],
        tools: vec![LlmToolSpec {
            name: "classify_claim".to_owned(),
            description: "Return a gate verdict".to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "verdict": { "type": "string" },
                    "score": { "type": "number" },
                },
                "required": ["verdict"],
            }),
        }],
        params,
        provider_options,
    }
}

fn sample_request_with_reordered_maps() -> LlmRequest {
    let mut request = sample_request();

    request.params.clear();
    request.params.insert(
        "sampling".to_owned(),
        json!({
            "seed": 7,
            "top_p": 0.8,
        }),
    );
    request.params.insert("temperature".to_owned(), json!(0.2));

    request.provider_options.clear();
    request.provider_options.insert(
        "openai".to_owned(),
        json!({
            "reasoning": {
                "summary": "auto",
                "effort": "medium",
            },
            "parallel_tool_calls": false,
        }),
    );

    request.tools[0].input_schema = json!({
        "required": ["verdict"],
        "properties": {
            "score": { "type": "number" },
            "verdict": { "type": "string" },
        },
        "type": "object",
    });

    request
}

fn semantic_mutations(request: &LlmRequest) -> Vec<(&'static str, LlmRequest)> {
    let mut mutations = Vec::new();

    let mut model = request.clone();
    model.model = ModelId::new("anthropic/claude-sonnet@2026-07-02").unwrap();
    mutations.push(("model", model));

    let mut purpose = request.clone();
    purpose.envelope.purpose = CallPurpose::AnswerGen;
    mutations.push(("purpose", purpose));

    let mut class = request.clone();
    class.envelope.class = CallClass::BestEffort;
    mutations.push(("class", class));

    let mut fallback_name = request.clone();
    if let CallClass::Durable { fallback } = &mut fallback_name.envelope.class {
        fallback.name = "different_fallback".to_owned();
    }
    mutations.push(("fallback_name", fallback_name));

    let mut fallback_config = request.clone();
    if let CallClass::Durable { fallback } = &mut fallback_config.envelope.class {
        fallback.config = Some(json!({ "mode": "strict" }));
    }
    mutations.push(("fallback_config", fallback_config));

    let mut tier_per_seat = request.clone();
    tier_per_seat.envelope.tier.per_seat = Some(ModelTierRef("large".to_owned()));
    mutations.push(("tier_per_seat", tier_per_seat));

    let mut tier_vault = request.clone();
    tier_vault.envelope.tier.vault_policy = Some(ModelTierRef("vault-large".to_owned()));
    mutations.push(("tier_vault", tier_vault));

    let mut tier_purpose = request.clone();
    tier_purpose.envelope.tier.purpose_default = Some(ModelTierRef("purpose-large".to_owned()));
    mutations.push(("tier_purpose", tier_purpose));

    let mut tier_global = request.clone();
    tier_global.envelope.tier.global_default = ModelTierRef("global-large".to_owned());
    mutations.push(("tier_global", tier_global));

    let mut response_format = request.clone();
    response_format.envelope.response_format = ResponseFormat::Text;
    mutations.push(("response_format", response_format));

    let mut locality = request.clone();
    locality.envelope.locality = ModelLocality::OwnServer;
    mutations.push(("locality", locality));

    let mut message = request.clone();
    message.messages[1].content[0] = ContentPart::Text {
        text: "Classify a different claim.".to_owned(),
    };
    mutations.push(("messages", message));

    let mut message_role = request.clone();
    message_role.messages[1].role = LlmMessageRole::Assistant;
    mutations.push(("message_role", message_role));

    let mut message_order = request.clone();
    message_order.messages.swap(0, 1);
    mutations.push(("message_order", message_order));

    let mut content_order = request.clone();
    content_order.messages[1].content.swap(0, 1);
    mutations.push(("content_order", content_order));

    let mut tools = request.clone();
    tools.tools[0].name = "route_tool".to_owned();
    mutations.push(("tools", tools));

    let mut tool_description = request.clone();
    tool_description.tools[0].description = "Return a routing verdict".to_owned();
    mutations.push(("tool_description", tool_description));

    let mut tool_schema = request.clone();
    tool_schema.tools[0].input_schema = json!({
        "type": "object",
        "properties": {
            "verdict": { "type": "boolean" },
        },
        "required": ["verdict"],
    });
    mutations.push(("tool_schema", tool_schema));

    let mut params = request.clone();
    params.params.insert("temperature".to_owned(), json!(0.7));
    mutations.push(("params", params));

    let mut provider_options = request.clone();
    provider_options.provider_options.insert(
        "openai".to_owned(),
        json!({
            "parallel_tool_calls": true,
            "reasoning": {
                "effort": "medium",
                "summary": "auto",
            },
        }),
    );
    mutations.push(("provider_options", provider_options));

    mutations
}

fn sample_envelope() -> CallEnvelope {
    CallEnvelope {
        seat_effort: None,
        scope: crate::llm::Scope::default(),
        purpose: CallPurpose::AutoCheck,
        class: CallClass::Durable {
            fallback: DeterministicFallback {
                name: "fail_closed_to_proposed".to_owned(),
                config: None,
            },
        },
        tier: TierPrecedence {
            per_seat: None,
            vault_policy: Some(ModelTierRef("cheap".to_owned())),
            purpose_default: Some(ModelTierRef("tiny".to_owned())),
            global_default: ModelTierRef("standard".to_owned()),
        },
        response_format: ResponseFormat::Json {
            schema: json!({
                "type": "object",
                "properties": {
                    "verdict": { "type": "string" },
                },
                "required": ["verdict"],
            }),
        },
        locality: ModelLocality::ThirdParty,
    }
}

// ---------------------------------------------------------------------------
// ONE-1296 auto-check seam: the request contract and the bounded wrapper's
// failure mapping. Every fixture stays local to this module; the tests above
// are untouched.
// ---------------------------------------------------------------------------

fn auto_check_candidate() -> AutoCheckCandidateOwned {
    AutoCheckCandidateOwned {
        signals: crate::llm::AutoCheckSignals::default(),
        predicate: "profile.name".to_owned(),
        value_preview: "Ada".to_owned(),
        source: ClaimSource::Generated,
        lineage: Some(SourceLineage::of(ClaimSource::Generated)),
        actor_class: "agent".to_owned(),
        sensitivity_band: Some(0),
        burst: Some(NormalizedBurstInputs {
            rate_ratio: 2.5,
            streak: 3,
        }),
    }
}

/// OF-037 is the CURRENT ruling and the older `BestEffort` line is stale
/// canon: an auto check is a DURABLE `AutoCheck` call answering in a JSON
/// schema on the purpose-default cheap tier. This test is what stops
/// `BestEffort` coming back.
#[test]
fn besteffort_rejected_stale_canon() {
    let candidate = auto_check_candidate();
    let request = auto_check_llm_request(
        "host-checker-v1",
        &candidate.borrowed(),
        "Host-provided checker instructions.",
    );

    assert_eq!(request.envelope.purpose, CallPurpose::AutoCheck);
    assert!(
        matches!(request.envelope.class, CallClass::Durable { .. }),
        "OF-037: an auto check is a durable call, not a best-effort one"
    );
    assert_ne!(
        request.envelope.class,
        CallClass::BestEffort,
        "BestEffort is stale canon for this purpose and must not return"
    );
    assert!(matches!(
        request.envelope.response_format,
        ResponseFormat::Json { .. }
    ));

    // The cheap tier arrives as the PURPOSE default, so a seat pin or a
    // vault policy still wins through `TierPrecedence::resolved`.
    assert!(request.envelope.tier.per_seat.is_none());
    assert!(request.envelope.tier.vault_policy.is_none());
    assert_eq!(
        request
            .envelope
            .tier
            .purpose_default
            .as_ref()
            .map(ModelTierRef::as_str),
        Some(AUTO_CHECK_PURPOSE_DEFAULT_TIER)
    );
    assert_eq!(
        request.envelope.tier.resolved().as_str(),
        AUTO_CHECK_PURPOSE_DEFAULT_TIER
    );

    // The manifest's opaque ref is carried through as the request's model
    // identity; the engine selects no model of its own.
    assert_eq!(
        request.model.as_str(),
        "auto-check/ref-686f73742d636865636b65722d7631@configured",
        "the original selector bytes ride the request without lossy sanitization"
    );

    // The candidate the gate saw is what the request describes.
    let rendered = format!("{:?}", request.messages);
    for expected in [
        "profile.name",
        "generated",
        "agent",
        "Ada",
        "rate_ratio: 2.5",
        "streak: 3",
    ] {
        assert!(
            rendered.contains(expected),
            "the auto-check request must describe {expected}"
        );
    }
}

#[test]
fn opaque_auto_checker_refs_have_distinct_model_pins_and_durable_identities() {
    let candidate = auto_check_candidate();
    let refs = [
        "checker:a",
        "checker/a",
        "checker?a",
        "checker.a",
        "checker_a",
        "",
        "configured",
        "ref-",
        "é",
        "e\u{301}",
        "a",
        " a",
        "a ",
        "\0",
        "0",
        "00",
    ];
    let requests: Vec<_> = refs
        .iter()
        .map(|selector| auto_check_llm_request(selector, &candidate.borrowed(), "Host policy."))
        .collect();
    let mut models = std::collections::BTreeSet::new();
    let mut hashes = std::collections::BTreeSet::new();
    for (index, request) in requests.iter().enumerate() {
        assert!(
            models.insert(request.model.clone()),
            "aliased {:?}",
            refs[index]
        );
        assert!(hashes.insert(request.canonical_hash().expect("canonical request")));
        assert_eq!(
            &auto_check_llm_request(refs[index], &candidate.borrowed(), "Host policy."),
            request,
            "the encoding is deterministic"
        );
        let pin = PinnedModelConfig {
            allowed: [request.model.clone()].into_iter().collect(),
            background_tier_enabled: true,
        };
        for (other_index, other) in requests.iter().enumerate() {
            assert_eq!(pin.admit(other).is_ok(), index == other_index);
        }
    }
}
