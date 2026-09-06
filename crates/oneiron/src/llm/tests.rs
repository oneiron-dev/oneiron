use super::*;
use proptest::prelude::*;
use serde_json::json;

proptest! {
    #[test]
    fn content_enum_roundtrips_between_history_and_generation(part in content_part_strategy()) {
        let history = LlmMessage {
            role: LlmMessageRole::User,
            content: vec![part.clone()],
        };
        let generation = LlmResponse {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![part.clone()],
            },
            usage: LlmUsage::zero(),
            finish_reason: FinishReason::Stop,
        };

        let history_part = serde_json::to_value(&history.content[0]).unwrap();
        let generation_part = serde_json::to_value(&generation.message.content[0]).unwrap();

        prop_assert_eq!(&history_part, &generation_part);

        let decoded_history = serde_json::from_value::<ContentPart>(history_part).unwrap();
        let decoded_generation = serde_json::from_value::<ContentPart>(generation_part).unwrap();
        prop_assert_eq!(&decoded_history, &decoded_generation);
        prop_assert_eq!(decoded_history, part);
    }
}

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
fn model_id_requires_provider_name_and_revision() {
    let model_id = "openai/gpt-4.1@2026-07-02".parse::<ModelId>().unwrap();
    assert_eq!(model_id.provider(), "openai");
    assert_eq!(model_id.name(), "gpt-4.1");
    assert_eq!(model_id.revision(), "2026-07-02");
    assert!("gpt-4.1@2026-07-02".parse::<ModelId>().is_err());
    assert!("openai/gpt-4.1".parse::<ModelId>().is_err());
    assert!("openai/@2026-07-02".parse::<ModelId>().is_err());
}

#[test]
fn role_model_defaults_resolve_default_model_for_each_role() {
    let defaults = RoleModelDefaults::default();
    let resolved: Vec<_> = [
        LlmRole::Orchestrator,
        LlmRole::Subagent,
        LlmRole::Summarizer,
    ]
    .into_iter()
    .map(|role| defaults.resolve(role).as_str().to_owned())
    .collect();

    assert_eq!(
        resolved,
        [
            "openai/gpt-4.1@2026-07-02",
            "openai/gpt-4.1-mini@2026-07-02",
            "openai/gpt-4.1-nano@2026-07-02",
        ]
    );
}

#[test]
fn role_model_defaults_prefer_user_override_for_each_role() {
    let mut defaults = RoleModelDefaults::default();
    let overrides = [
        (
            LlmRole::Orchestrator,
            ModelId::new("anthropic/claude-opus@2026-07-02").unwrap(),
        ),
        (
            LlmRole::Subagent,
            ModelId::new("anthropic/claude-sonnet@2026-07-02").unwrap(),
        ),
        (
            LlmRole::Summarizer,
            ModelId::new("local/fixture@2026-07-06").unwrap(),
        ),
    ];

    for (role, model) in &overrides {
        let _ = defaults.set_override(*role, model.clone());
    }

    let resolved: Vec<_> = [
        LlmRole::Orchestrator,
        LlmRole::Subagent,
        LlmRole::Summarizer,
    ]
    .into_iter()
    .map(|role| defaults.resolve(role).as_str().to_owned())
    .collect();

    assert_eq!(
        resolved,
        overrides
            .iter()
            .map(|(_, model)| model.as_str().to_owned())
            .collect::<Vec<_>>()
    );
}

#[test]
fn tier_precedence_resolves_in_contract_order() {
    let global = ModelTierRef("global".to_owned());
    let purpose = ModelTierRef("purpose".to_owned());
    let vault = ModelTierRef("vault".to_owned());
    let per_call = ModelTierRef("per-call".to_owned());

    let mut precedence = TierPrecedence {
        per_call: None,
        vault_policy: None,
        purpose_default: None,
        global_default: global.clone(),
    };
    assert_eq!(precedence.resolved(), &global);

    precedence.purpose_default = Some(purpose.clone());
    assert_eq!(precedence.resolved(), &purpose);

    precedence.vault_policy = Some(vault.clone());
    assert_eq!(precedence.resolved(), &vault);

    precedence.per_call = Some(per_call.clone());
    assert_eq!(precedence.resolved(), &per_call);
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

#[test]
fn reasoning_effort_round_trips_contract_wire_values() {
    let cases = [
        (ReasoningEffort::None, "none"),
        (ReasoningEffort::Low, "low"),
        (ReasoningEffort::Medium, "medium"),
        (ReasoningEffort::High, "high"),
        (ReasoningEffort::XHigh, "xhigh"),
    ];

    for (effort, wire) in cases {
        assert_eq!(serde_json::to_value(effort).unwrap(), json!(wire));
        assert_eq!(
            serde_json::from_value::<ReasoningEffort>(json!(wire)).unwrap(),
            effort
        );
    }
}

#[test]
fn unsupported_capability_display_uses_stable_capability_name() {
    let unsupported = UnsupportedCapability {
        capability: LlmCapability::ToolCalling,
        model: Some(ModelId::new("openai/gpt-4.1@2026-07-02").unwrap()),
        reason: Some("catalog entry lacks tools".to_owned()),
    };

    assert_eq!(
        unsupported.to_string(),
        "tool_calling for openai/gpt-4.1@2026-07-02: catalog entry lacks tools"
    );
}

#[test]
fn stream_eof_before_done_becomes_stream_cut() {
    let mut stream = LlmStream::new(ReadyLlmStream::new([]));

    let item = poll_stream_once(&mut stream).expect("stream cut error");
    assert!(matches!(
        item,
        Err(LlmError::Retryable(RetryableLlmError::StreamCut))
    ));
    assert!(poll_stream_once(&mut stream).is_none());
}

#[test]
fn stream_done_is_terminal() {
    let done = LlmStreamEvent::Done {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: "done".to_owned(),
            }],
        },
        usage: LlmUsage::zero(),
        finish_reason: FinishReason::Stop,
    };
    let after_done = LlmStreamEvent::TextStart {
        part_id: "late".to_owned(),
    };
    let mut stream = LlmStream::new(ReadyLlmStream::new([Ok(done.clone()), Ok(after_done)]));

    assert_eq!(poll_stream_once(&mut stream).unwrap().unwrap(), done);
    assert!(poll_stream_once(&mut stream).is_none());
}

fn content_part_strategy() -> impl Strategy<Value = ContentPart> {
    prop_oneof![
        short_string().prop_map(|text| ContentPart::Text { text }),
        (short_string(), prop::option::of(short_string()))
            .prop_map(|(text, signature)| { ContentPart::Reasoning { text, signature } }),
        (id_string(), name_string(), json_value_strategy()).prop_map(|(call_id, name, input)| {
            ContentPart::ToolCall {
                call_id,
                name,
                input,
            }
        }),
        (id_string(), json_value_strategy(), any::<bool>()).prop_map(
            |(call_id, output, is_error)| ContentPart::ToolResult {
                call_id,
                output,
                is_error,
            }
        ),
        (media_type_strategy(), image_content_strategy())
            .prop_map(|(media_type, image)| { ContentPart::Image { media_type, image } }),
    ]
}

fn json_value_strategy() -> impl Strategy<Value = JsonValue> {
    let leaf = prop_oneof![
        Just(JsonValue::Null),
        any::<bool>().prop_map(JsonValue::Bool),
        (0_i64..10_000).prop_map(|value| json!(value)),
        short_string().prop_map(JsonValue::String),
    ];

    leaf.prop_recursive(3, 16, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(JsonValue::Array),
            prop::collection::btree_map(name_string(), inner, 0..4).prop_map(|entries| {
                let mut object = JsonMap::new();
                for (key, value) in entries {
                    object.insert(key, value);
                }
                JsonValue::Object(object)
            }),
        ]
    })
}

fn image_content_strategy() -> impl Strategy<Value = ImageContent> {
    prop_oneof![
        short_string().prop_map(|data| ImageContent::Base64 { data }),
        short_string().prop_map(|path| ImageContent::Url {
            url: format!("https://example.com/{path}"),
        }),
    ]
}

fn short_string() -> impl Strategy<Value = String> {
    "[ -~]{0,32}".prop_map(|value| value)
}

fn id_string() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_.:-]{1,24}".prop_map(|value| value)
}

fn name_string() -> impl Strategy<Value = String> {
    "[a-zA-Z][a-zA-Z0-9_-]{0,23}".prop_map(|value| value)
}

fn media_type_strategy() -> impl Strategy<Value = String> {
    prop_oneof![Just("image/png".to_owned()), Just("image/jpeg".to_owned())]
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

    let mut tier_per_call = request.clone();
    tier_per_call.envelope.tier.per_call = Some(ModelTierRef("large".to_owned()));
    mutations.push(("tier_per_call", tier_per_call));

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
        purpose: CallPurpose::AutoCheck,
        class: CallClass::Durable {
            fallback: DeterministicFallback {
                name: "fail_closed_to_proposed".to_owned(),
                config: None,
            },
        },
        tier: TierPrecedence {
            per_call: None,
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

#[test]
fn backend_trait_requires_lease_argument() {
    struct Backend;

    impl LlmBackend for Backend {
        fn generate<'a>(
            &'a self,
            _request: LlmRequest,
            _lease: &'a BudgetLease,
        ) -> LlmGenerateFuture<'a> {
            Box::pin(async {
                Ok(LlmResponse {
                    message: LlmMessage {
                        role: LlmMessageRole::Assistant,
                        content: vec![ContentPart::Text {
                            text: "ok".to_owned(),
                        }],
                    },
                    usage: LlmUsage::zero(),
                    finish_reason: FinishReason::Stop,
                })
            })
        }

        fn stream<'a>(
            &'a self,
            _request: LlmRequest,
            _lease: &'a BudgetLease,
        ) -> LlmStreamResult<'a> {
            Ok(LlmStream::new(EmptyLlmStream))
        }
    }

    struct DenyingBackend;

    impl LlmBackend for DenyingBackend {
        fn generate<'a>(
            &'a self,
            _request: LlmRequest,
            _lease: &'a BudgetLease,
        ) -> LlmGenerateFuture<'a> {
            Box::pin(async { Err(BudgetDenied::AdmissionDenied.into()) })
        }

        fn stream<'a>(
            &'a self,
            _request: LlmRequest,
            _lease: &'a BudgetLease,
        ) -> LlmStreamResult<'a> {
            Err(BudgetDenied::AdmissionDenied.into())
        }
    }

    struct EmptyLlmStream;

    impl Stream for EmptyLlmStream {
        type Item = LlmResult<LlmStreamEvent>;

        fn poll_next(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Ready(None)
        }
    }

    let backend = Backend;
    let lease = BudgetLease::for_test("lease-1");
    let _stream = backend.stream(sample_request(), &lease).unwrap();

    let setup_error = match DenyingBackend.stream(sample_request(), &lease) {
        Ok(_) => panic!("stream setup should fail"),
        Err(error) => error,
    };
    assert!(matches!(
        setup_error,
        LlmError::BudgetDenied(BudgetDenied::AdmissionDenied)
    ));

    let _backend: Box<dyn LlmBackend> = Box::new(Backend);
}

struct ReadyLlmStream {
    events: std::collections::VecDeque<LlmResult<LlmStreamEvent>>,
}

impl ReadyLlmStream {
    fn new(events: impl IntoIterator<Item = LlmResult<LlmStreamEvent>>) -> Self {
        Self {
            events: events.into_iter().collect(),
        }
    }
}

impl Stream for ReadyLlmStream {
    type Item = LlmResult<LlmStreamEvent>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Ready(self.events.pop_front())
    }
}

fn poll_stream_once(stream: &mut LlmStream<'_>) -> Option<LlmResult<LlmStreamEvent>> {
    let waker: &std::task::Waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match Pin::new(stream).poll_next(&mut cx) {
        std::task::Poll::Ready(item) => item,
        std::task::Poll::Pending => panic!("test stream should not pend"),
    }
}

// ---------------------------------------------------------------------------
// ONE-1296 auto-check seam: the request contract and the bounded wrapper's
// failure mapping. Every fixture stays local to this module; the tests above
// are untouched.
// ---------------------------------------------------------------------------

fn auto_check_candidate() -> AutoCheckCandidateOwned {
    AutoCheckCandidateOwned {
        predicate: "profile.name".to_owned(),
        value_preview: "Ada".to_owned(),
        source: ClaimSource::Generated,
        actor_class: "agent".to_owned(),
        sensitivity_band: Some(0),
    }
}

struct FixedAutoChecker {
    outcome: AutoCheckOutcome,
}

impl FixedAutoChecker {
    fn new(outcome: AutoCheckOutcome) -> Self {
        Self { outcome }
    }
}

impl AutoChecker for FixedAutoChecker {
    fn check(&self, _candidate: &AutoCheckCandidate<'_>) -> AutoCheckOutcome {
        self.outcome.clone()
    }
}

/// A host implementation that unwinds instead of answering.
struct PanickingAutoChecker;

impl AutoChecker for PanickingAutoChecker {
    fn check(&self, _candidate: &AutoCheckCandidate<'_>) -> AutoCheckOutcome {
        panic!("host auto checker panicked");
    }
}

/// A host implementation that answers, but far too late to be waited for.
struct SlowAutoChecker;

impl AutoChecker for SlowAutoChecker {
    fn check(&self, _candidate: &AutoCheckCandidate<'_>) -> AutoCheckOutcome {
        std::thread::sleep(Duration::from_millis(AUTO_CHECKER_DEADLINE_MS + 500));
        AutoCheckOutcome::Allow
    }
}

fn bounded(checker: impl AutoChecker) -> BoundedAutoChecker {
    BoundedAutoChecker::new(Arc::new(checker))
}

/// OF-037 is the CURRENT ruling and the older `BestEffort` line is stale
/// canon: an auto check is a DURABLE `AutoCheck` call answering in a JSON
/// schema on the purpose-default cheap tier. This test is what stops
/// `BestEffort` coming back.
#[test]
fn besteffort_rejected_stale_canon() {
    let candidate = auto_check_candidate();
    let request = auto_check_llm_request("host-checker-v1", &candidate.borrowed());

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

    // The cheap tier arrives as the PURPOSE default, so a per-call pin or a
    // vault policy still wins through `TierPrecedence::resolved`.
    assert!(request.envelope.tier.per_call.is_none());
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
    assert!(
        request.model.as_str().contains("host-checker-v1"),
        "the opaque checker ref rides the request: {}",
        request.model
    );

    // The candidate the gate saw is what the request describes.
    let rendered = format!("{:?}", request.messages);
    for expected in ["profile.name", "generated", "agent", "Ada"] {
        assert!(
            rendered.contains(expected),
            "the auto-check request must describe {expected}"
        );
    }
}

#[test]
fn auto_check_candidate_round_trips_between_borrowed_and_owned() {
    let owned = auto_check_candidate();
    let borrowed = owned.borrowed();
    assert_eq!(AutoCheckCandidateOwned::from(&borrowed), owned);
    assert_eq!(borrowed.predicate, "profile.name");
    assert_eq!(borrowed.source, ClaimSource::Generated);
}

#[test]
fn bounded_auto_checker_passes_a_clear_verdict_through() {
    let candidate = auto_check_candidate();

    assert_eq!(
        bounded(FixedAutoChecker::new(AutoCheckOutcome::Allow)).check(&candidate.borrowed()),
        AutoCheckOutcome::Allow
    );

    let held = bounded(FixedAutoChecker::new(AutoCheckOutcome::Hold {
        reasons: vec!["  hedged verdict  ".to_owned(), String::new()],
    }))
    .check(&candidate.borrowed());
    assert_eq!(
        held,
        AutoCheckOutcome::Hold {
            reasons: vec!["hedged verdict".to_owned()]
        },
        "a hold keeps its reasons, trimmed and blank-dropped"
    );
}

/// Every way a checker can fail to produce a usable verdict lands on the SAME
/// fail-closed answer, and none of them unwinds into the caller.
#[test]
fn bounded_auto_checker_maps_every_failure_to_unavailable() {
    let candidate = auto_check_candidate();

    // The host's own word for budget denial, fatal model error, or nothing
    // configured to answer at all.
    assert_eq!(
        bounded(FixedAutoChecker::new(AutoCheckOutcome::Unavailable)).check(&candidate.borrowed()),
        AutoCheckOutcome::Unavailable
    );

    // A panic is captured off the caller's stack.
    assert_eq!(
        bounded(PanickingAutoChecker).check(&candidate.borrowed()),
        AutoCheckOutcome::Unavailable
    );

    // A hold that names no surviving reason is a MALFORMED verdict: a refusal
    // the receipt could not explain is not a refusal the gate will carry.
    assert_eq!(
        bounded(FixedAutoChecker::new(AutoCheckOutcome::Hold {
            reasons: vec!["   ".to_owned()],
        }))
        .check(&candidate.borrowed()),
        AutoCheckOutcome::Unavailable
    );
    assert_eq!(
        AutoCheckOutcome::Hold {
            reasons: Vec::new()
        }
        .normalized(),
        AutoCheckOutcome::Unavailable
    );
}

#[test]
fn bounded_auto_checker_stops_waiting_at_the_deadline() {
    let candidate = auto_check_candidate();
    let started = std::time::Instant::now();
    let outcome = bounded(SlowAutoChecker).check(&candidate.borrowed());
    let elapsed = started.elapsed();

    assert_eq!(outcome, AutoCheckOutcome::Unavailable);
    assert!(
        elapsed >= Duration::from_millis(AUTO_CHECKER_DEADLINE_MS),
        "the wrapper waits for the full deadline before giving up: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(AUTO_CHECKER_DEADLINE_MS * 3),
        "the wrapper must not wait for a slow host to finish: {elapsed:?}"
    );
}

/// A host cannot write an unbounded gate-decision receipt through its hold
/// reasons, and truncation never splits a character.
#[test]
fn hold_reasons_are_bounded_before_they_reach_a_receipt() {
    let mut reasons: Vec<String> = (0..32).map(|index| format!("reason-{index}")).collect();
    reasons.insert(0, "é".repeat(AUTO_CHECK_HOLD_REASON_MAX_BYTES));

    let normalized = AutoCheckOutcome::Hold { reasons }.normalized();
    let AutoCheckOutcome::Hold { reasons } = normalized else {
        panic!("a hold naming reasons stays a hold");
    };

    assert_eq!(reasons.len(), AUTO_CHECK_MAX_HOLD_REASONS);
    assert!(reasons[0].len() <= AUTO_CHECK_HOLD_REASON_MAX_BYTES);
    assert!(
        reasons[0].chars().all(|character| character == 'é'),
        "truncation must land on a character boundary"
    );
}
