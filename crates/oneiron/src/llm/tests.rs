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
        resets_at: Vec::new(),
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
                    signature: None,
                }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![
                    ContentPart::Text {
                        text: "Classify this claim.".to_owned(),
                        signature: None,
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
        host_segments: None,
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
        signature: None,
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
            seat: None,
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
        host_keyless: false,
        host_paid: false,
    }
}

/// The auto check reads the candidate the write gate saw: its predicate, source, actor class,
/// value preview and burst inputs. Rewritten from `besteffort_rejected_stale_canon` (rule D with
/// a successor): 16a66ff161c (#2496) removed the auto-check request builder, and the typed
/// `AutoCheckDecisions` (4c541a578f5, #1608) hands the candidate to its provider as the decision
/// call's state. The request-envelope checks (call class, JSON schema, purpose tier, model id)
/// have no successor and are not carried.
#[test]
fn the_auto_checker_reads_the_candidate_the_gate_saw() {
    use crate::llm::decision::{
        DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionDial,
        DecisionProvider, DecisionRung, HeldLadder, ProviderDecision, ProviderPin,
    };
    use std::sync::{Arc, Mutex};

    /// Records the state of the one call it answers, and allows.
    struct Capture(Mutex<Option<serde_json::Value>>);
    impl DecisionProvider for Capture {
        fn pin(&self) -> ProviderPin {
            ProviderPin {
                rung: DecisionRung::Big,
                model: "test-auto-checker".into(),
                version: "1".into(),
            }
        }
        fn decide(&self, call: &DecisionCall<'_>) -> crate::Result<ProviderDecision> {
            *self.0.lock().unwrap() = Some(call.state.clone());
            Ok(ProviderDecision {
                answer: DecisionAnswer::Choice("allow".into()),
                probability: Some(1.0),
                paired: None,
                person: None,
                served: None,
                cost_per_thousand: None,
            })
        }
    }
    struct NoNotes;
    impl AutoCheckNotes for NoNotes {
        fn hold_reasons(
            &self,
            _: &AutoCheckCandidate<'_>,
            _: std::time::Instant,
        ) -> crate::Result<Vec<String>> {
            Ok(Vec::new())
        }
    }

    let capture = Arc::new(Capture(Mutex::new(None)));
    let mut ladder = HeldLadder::unstaffed();
    ladder.big = Some(Arc::clone(&capture) as Arc<dyn DecisionProvider>);
    let checker = BoundedAutoChecker::new(AutoCheckDecisions {
        ladder,
        principal: crate::test_util::entity(0x5e),
        dial: DecisionDial {
            first: DecisionRung::Big,
            ceiling: DecisionRung::Big,
            band: DecisionBand::default(),
        },
        bands: DecisionBandPolicy::default(),
        wording: "May this write approve itself?".into(),
        notes: Arc::new(NoNotes),
        calibrated: None,
    });
    let candidate = AutoCheckCandidateOwned {
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
    };
    checker.check(&candidate.borrowed());
    let state = capture
        .0
        .lock()
        .unwrap()
        .clone()
        .expect("the auto check asked its provider");

    // The candidate the gate saw is what the request describes.
    let rendered = serde_json::to_string_pretty(&state).unwrap();
    for expected in [
        "profile.name",
        "generated",
        "agent",
        "Ada",
        "\"rate_ratio\": 2.5",
        "\"streak\": 3",
    ] {
        assert!(
            rendered.contains(expected),
            "the auto-check request must describe {expected}"
        );
    }
}
