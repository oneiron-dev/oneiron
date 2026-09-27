use super::*;
use futures_core::Stream;
use oneiron::llm::LlmCatalogCost;
use oneiron::llm::registry::{ModelRegistryRow, ModelWireFormat};
use oneiron::*;
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
fn ready<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("fixture pending"),
    }
}
struct Sequence(VecDeque<LlmResult<GeminiFrame>>);
impl Stream for Sequence {
    type Item = LlmResult<GeminiFrame>;
    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.0.pop_front())
    }
}
struct Transport;
fn fixture() -> Value {
    json!({"candidates":[{"content":{"parts":[{"text":"plan","thought":true,"thoughtSignature":"signed"},{"text":"hello"},{"functionCall":{"id":"call-1","name":"double","args":{"n":4}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":2,"candidatesTokenCount":3,"thoughtsTokenCount":1}})
}
impl GeminiTransport for Transport {
    fn execute<'a>(
        &'a self,
        request: GeminiHttpRequest,
        lease: &'a BudgetLease,
    ) -> GeminiFuture<'a> {
        assert!(!lease.id().is_empty());
        assert!(request.path.ends_with(":generateContent"));
        assert_eq!(
            request.body["generationConfig"]["responseMimeType"],
            json!("application/json")
        );
        Box::pin(async {
            Ok(GeminiHttpResponse {
                status: 200,
                body: fixture(),
            })
        })
    }
    fn stream<'a>(
        &'a self,
        request: GeminiHttpRequest,
        lease: &'a BudgetLease,
    ) -> LlmResult<GeminiProviderStream<'a>> {
        assert!(!lease.id().is_empty());
        assert!(request.path.ends_with(":streamGenerateContent?alt=sse"));
        Ok(Box::pin(Sequence(
            vec![
                Ok(GeminiFrame::Status(GeminiHttpResponse {
                    status: 200,
                    body: Value::Null,
                })),
                Ok(GeminiFrame::Chunk(
                    json!({"candidates":[{"content":{"parts":[{"thoughtSignature":"metadata"}]}}]}),
                )),
                Ok(GeminiFrame::Chunk(fixture())),
            ]
            .into(),
        )))
    }
}
#[test]
fn generate_and_stream_conform_with_lease_and_catalog_only_vendor_swap() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    for provider in ["google", "second-vendor"] {
        let model = ModelId::new(format!("{provider}/gemini-model@r1")).unwrap();
        vault
            .put_model_registry_row(&ModelRegistryRow {
                version: 1,
                wire: ModelWireFormat::Gemini,
                catalog: LlmCatalogEntry {
                    model: model.clone(),
                    display_name: provider.into(),
                    locality: ModelLocality::ThirdParty,
                    context_window_tokens: 8192,
                    max_output_tokens: Some(1024),
                    cost: Some(LlmCatalogCost {
                        input_per_million: "1".into(),
                        output_per_million: "2".into(),
                        cache_read_per_million: None,
                        cache_write_per_million: None,
                    }),
                    capabilities: vec![
                        LlmCapability::Streaming,
                        LlmCapability::JsonResponse,
                        LlmCapability::ToolCalling,
                        LlmCapability::Reasoning,
                    ],
                    metadata: BTreeMap::new(),
                },
                scores: BTreeMap::new(),
                fetched_at: BTreeMap::new(),
            })
            .unwrap();
        let row = vault.model_registry_row(&model).unwrap().unwrap();
        let backend = GeminiBackend::from_registry(&vault, Transport).unwrap();
        let request = LlmRequest {
            model,
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                purpose: CallPurpose::AnswerGen,
                class: CallClass::BestEffort,
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::AnswerGen,
                    ModelTierRef("default".into()),
                ),
                response_format: ResponseFormat::Json {
                    schema: json!({"type":"object"}),
                },
                locality: ModelLocality::ThirdParty,
            },
            messages: vec![LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: "test".into(),
                }],
            }],
            tools: vec![],
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        };
        let guard = BudgetGuard::with_reserve_units("g", 100, 10, BudgetExhaustionPolicy::Suspend);
        // Removing a capability in catalog data refuses before the transport runs.
        let mut restricted = row.clone();
        restricted.catalog.capabilities.clear();
        vault.put_model_registry_row(&restricted).unwrap();
        let denied = GeminiBackend::from_registry(&vault, Transport).unwrap();
        let lease = guard.admit_for_request(&request).unwrap().lease;
        assert!(matches!(
            ready(denied.generate(request.clone(), &lease)),
            Err(LlmError::Fatal(FatalLlmError::Unsupported(_)))
        ));
        assert!(matches!(
            denied.stream(request.clone(), &lease),
            Err(LlmError::Fatal(FatalLlmError::Unsupported(_)))
        ));
        guard.abort(&lease).unwrap();
        vault.put_model_registry_row(&row).unwrap();
        let lease = guard.admit_for_request(&request).unwrap().lease;
        let generated = ready(backend.generate(request.clone(), &lease)).unwrap();
        assert_eq!(generated.message.content.len(), 3);
        guard.settle_per_call(&lease, &generated.usage).unwrap();
        assert_eq!(guard.read().used_units, 6);
        let lease = guard.admit_for_request(&request).unwrap().lease;
        let ledger = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut bus = oneiron::llm::LlmEventBus::new(Box::new(Ledger(ledger.clone())));
        let mut subscriber = bus.subscribe();
        ready(bus.drive(backend.stream(request.clone(), &lease).unwrap())).unwrap();
        let mut events = Vec::new();
        while let Poll::Ready(Some(event)) =
            Pin::new(&mut subscriber).poll_next(&mut Context::from_waker(Waker::noop()))
        {
            events.push(event);
        }
        assert_eq!(*ledger.lock().unwrap(), vec![generated.clone()]);
        assert!(matches!(
            events.first(),
            Some(LlmStreamEvent::ReasoningStart { .. })
        ));
        assert!(
            events.iter().any(
                |e| matches!(e,LlmStreamEvent::ToolCallEnd{input,..}if input==&json!({"n":4}))
            )
        );
        let terminals: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, LlmStreamEvent::Done { .. }))
            .collect();
        assert_eq!(terminals.len(), 1);
        let LlmStreamEvent::Done { message, usage, .. } = terminals[0] else {
            unreachable!()
        };
        assert_eq!(message, &generated.message);
        guard.settle_per_call(&lease, usage).unwrap();
        assert_eq!(guard.read().reserved_units, 0);
        for status in [401, 402, 429] {
            let failed = GeminiBackend::from_registry(&vault, StatusTransport(status)).unwrap();
            let lease = guard.admit_for_request(&request).unwrap().lease;
            let generated = ready(failed.generate(request.clone(), &lease)).unwrap_err();
            let mut cut = failed.stream(request.clone(), &lease).unwrap();
            let Poll::Ready(Some(Err(streamed))) =
                Pin::new(&mut cut).poll_next(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("missing typed stream error")
            };
            for error in [generated, streamed] {
                match status {
                    401 => assert!(matches!(error, LlmError::Fatal(FatalLlmError::Auth))),
                    402 => assert!(matches!(error, LlmError::BudgetDenied(_))),
                    429 => assert!(matches!(
                        error,
                        LlmError::Retryable(RetryableLlmError::RateLimited { .. })
                    )),
                    _ => unreachable!(),
                }
            }
            assert!(matches!(
                Pin::new(&mut cut).poll_next(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(None)
            ));
            drop(cut);
            guard.abort(&lease).unwrap();
            assert_eq!(guard.read().reserved_units, 0);
        }
    }
    assert!(matches!(
        classify_status(429, &json!({})),
        LlmError::Retryable(_)
    ));
    assert!(matches!(
        classify_status(401, &json!({})),
        LlmError::Fatal(_)
    ));
    assert!(matches!(
        classify_status(402, &json!({})),
        LlmError::BudgetDenied(_)
    ));
}
#[test]
fn empty_and_blocked_outputs_fail_typed_instead_of_done() {
    assert!(matches!(
        parse_response(json!({"candidates":[{"content":{"parts":[]},"finishReason":"STOP"}]})),
        Err(LlmError::Fatal(FatalLlmError::EmptyResponse))
    ));
    assert!(matches!(
        GeminiAccumulator::default().push(json!({"promptFeedback":{"blockReason":"SAFETY"}})),
        Err(LlmError::Fatal(FatalLlmError::ContentFiltered))
    ));
}

struct StatusTransport(u16);
impl GeminiTransport for StatusTransport {
    fn execute<'a>(&'a self, _: GeminiHttpRequest, _: &'a BudgetLease) -> GeminiFuture<'a> {
        Box::pin(async move {
            Ok(GeminiHttpResponse {
                status: self.0,
                body: json!({}),
            })
        })
    }
    fn stream<'a>(
        &'a self,
        _: GeminiHttpRequest,
        _: &'a BudgetLease,
    ) -> LlmResult<GeminiProviderStream<'a>> {
        Ok(Box::pin(Sequence(
            vec![Ok(GeminiFrame::Status(GeminiHttpResponse {
                status: self.0,
                body: json!({}),
            }))]
            .into(),
        )))
    }
}

struct Ledger(std::sync::Arc<std::sync::Mutex<Vec<LlmResponse>>>);
impl oneiron::llm::TerminalSink for Ledger {
    fn record(&mut self, response: &LlmResponse) -> LlmResult<()> {
        self.0.lock().unwrap().push(response.clone());
        Ok(())
    }
}

#[test]
fn signature_metadata_does_not_hide_unsupported_content() {
    let mut accumulator = GeminiAccumulator::default();
    assert!(accumulator.push(json!({"candidates":[{"content":{"parts":[{"thoughtSignature":"sig","inlineData":{}}]}}]})).is_err());
}

#[test]
fn interleaved_parts_keep_provider_order_across_chunks() {
    let first = json!({"candidates":[{"content":{"parts":[
        {"text":"A"},
        {"functionCall":{"id":"call-1","name":"f","args":{}}},
        {"text":"B"}
    ]}}]});
    let mut accumulator = GeminiAccumulator::default();
    let mut events = accumulator.push(first).unwrap();
    events.extend(
        accumulator
            .push(json!({"candidates":[{"content":{"parts":[
        {"text":"C"}
    ]},"finishReason":"STOP"}]}))
            .unwrap(),
    );
    let Some(LlmStreamEvent::Done { message, .. }) = events.last() else {
        panic!("missing terminal");
    };
    assert_eq!(
        message.content,
        vec![
            ContentPart::Text { text: "A".into() },
            ContentPart::ToolCall {
                call_id: "call-1".into(),
                name: "f".into(),
                input: json!({})
            },
            ContentPart::Text { text: "BC".into() },
        ]
    );
    let starts: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            LlmStreamEvent::TextStart { part_id } => Some(part_id),
            _ => None,
        })
        .collect();
    assert_eq!(starts.len(), 2);
    assert_eq!(
        starts
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        2
    );
}

#[test]
fn consecutive_gemini_deltas_match_one_shot_reconstruction() {
    let mut accumulator = GeminiAccumulator::default();
    let mut events = Vec::new();
    for (text, thought) in [
        ("think", true),
        (" more", true),
        ("hello", false),
        (" world", false),
    ] {
        events.extend(
            accumulator
                .push(
                    json!({"candidates":[{"content":{"parts":[{"text":text,"thought":thought}]}}]}),
                )
                .unwrap(),
        );
    }
    let tail = json!({"candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":2,"thoughtsTokenCount":1}});
    events.extend(accumulator.push(tail.clone()).unwrap());
    let mut one_shot = tail;
    one_shot["candidates"][0]["content"] =
        json!({"parts":[{"text":"think more","thought":true},{"text":"hello world"}]});
    let expected = parse_response(one_shot).unwrap();
    let Some(LlmStreamEvent::Done {
        message,
        usage,
        finish_reason,
    }) = events.last()
    else {
        panic!("terminal missing");
    };
    assert_eq!(message, &expected.message);
    assert_eq!(usage, &expected.usage);
    assert_eq!(finish_reason, &expected.finish_reason);
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, LlmStreamEvent::TextStart { .. }))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, LlmStreamEvent::ReasoningStart { .. }))
            .count(),
        1
    );
}

#[test]
fn parameterless_gemini_tools_default_only_missing_args() {
    let body = json!({"candidates":[{"content":{"parts":[{"functionCall":{"id":"c","name":"clock"}}]},"finishReason":"STOP"}]});
    let expected = vec![ContentPart::ToolCall {
        call_id: "c".into(),
        name: "clock".into(),
        input: json!({}),
    }];
    assert_eq!(
        parse_response(body.clone()).unwrap().message.content,
        expected
    );
    let events = GeminiAccumulator::default().push(body.clone()).unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, LlmStreamEvent::ToolCallEnd { input, .. } if input == &json!({})))
    );
    assert!(
        matches!(events.last(), Some(LlmStreamEvent::Done { message, finish_reason: FinishReason::ToolCalls, .. }) if message.content == expected)
    );
    for args in [json!(null), json!([]), json!("{}"), json!(3)] {
        let mut invalid = body.clone();
        invalid["candidates"][0]["content"]["parts"][0]["functionCall"]["args"] = args;
        assert!(matches!(
            parse_response(invalid.clone()),
            Err(LlmError::Fatal(FatalLlmError::InvalidRequest))
        ));
        assert!(matches!(
            GeminiAccumulator::default().push(invalid),
            Err(LlmError::Fatal(FatalLlmError::InvalidRequest))
        ));
    }
}

#[test]
fn routed_gemini_verdict_omits_cached_prefix_in_final_wire() {
    use oneiron::llm::routing::{
        DescriptionJudge, DescriptionJudgment, DescriptionPolicy, ModelDescription, OwnerModelLine,
        SeatSettings, VerdictPayload,
    };
    struct Judge;
    impl DescriptionJudge for Judge {
        fn judge(
            &self,
            _: &str,
            _: &ModelId,
            _: &str,
            _: oneiron::llm::ReasoningEffort,
        ) -> DescriptionJudgment {
            DescriptionJudgment {
                fitness: 1,
                reason: "fixture".into(),
            }
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let model = ModelId::new("google/gemini-model@r1").unwrap();
    vault
        .set_description_policy(&DescriptionPolicy {
            models: vec![ModelDescription {
                model: model.clone(),
                wire: ModelWireFormat::Gemini,
                locality: ModelLocality::ThirdParty,
                owner: Some(OwnerModelLine {
                    model: model.clone(),
                    text: "fixture".into(),
                    expected_quality: 500_000,
                }),
                public_benchmark: None,
                vendor: None,
                effort_ladder: vec![oneiron::llm::ReasoningEffort::None],
            }],
            contradiction_margin_millionths: 100_000,
            vault_effort: None,
            purpose_effort: Default::default(),
            global_effort: None,
        })
        .unwrap();
    let catalog = LlmCatalogEntry {
        model,
        display_name: "Gemini".into(),
        locality: ModelLocality::ThirdParty,
        context_window_tokens: 8192,
        max_output_tokens: None,
        cost: None,
        capabilities: vec![LlmCapability::JsonResponse],
        metadata: Default::default(),
    };
    let request = LlmRequest {
        model: ModelId::new("google/old-model@r1").unwrap(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::AutoCheck,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AutoCheck,
                ModelTierRef("default".into()),
            ),
            response_format: ResponseFormat::Json {
                schema: json!({"type":"object"}),
            },
            locality: ModelLocality::ThirdParty,
        },
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: "old seat prefix".into(),
                }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: "old user turn".into(),
                }],
            },
        ],
        tools: vec![],
        params: std::collections::BTreeMap::from([
            ("cachedContent".into(), json!("cachedContents/old")),
            ("thinkingConfig".into(), json!({"thinkingBudget":4096})),
        ]),
        provider_options: std::collections::BTreeMap::from([(
            "gemini".into(),
            json!({
                "cachedContent":"cachedContents/seat-prefix", "safetySettings": []
            }),
        )]),
    };
    let routed = vault
        .routed_verdict_request(
            "schema check",
            &Judge,
            &SeatSettings::default(),
            request,
            VerdictPayload {
                instructions: Some("current instructions".into()),
                input: vec![ContentPart::Text {
                    text: "current verdict".into(),
                }],
            },
        )
        .unwrap();
    let wire = super::wire::build_request(&catalog, &routed, false).unwrap();
    assert!(wire.body.get("cachedContent").is_none());
    assert!(wire.body["generationConfig"].get("cachedContent").is_none());
    assert!(
        wire.body["generationConfig"]
            .get("thinkingConfig")
            .is_none()
    );
    assert_eq!(wire.body["safetySettings"], json!([]));
    assert_eq!(
        wire.body["systemInstruction"]["parts"][0]["text"],
        json!("current instructions")
    );
    assert_eq!(
        wire.body["contents"][0]["parts"][0]["text"],
        json!("current verdict")
    );
    assert_eq!(
        wire.body["generationConfig"]["responseMimeType"],
        json!("application/json")
    );
    assert_eq!(
        wire.body["generationConfig"]["responseJsonSchema"],
        json!({"type":"object"})
    );
    assert!(!wire.body.to_string().contains("old seat prefix"));
    assert!(!wire.body.to_string().contains("old user turn"));
    assert!(!wire.body.to_string().contains("cachedContents/seat-prefix"));
}

#[test]
fn gemini_native_seat_pins_win_normalized_caller_aliases_on_both_verbs() {
    use oneiron::llm::routing::{
        DescriptionJudge, DescriptionJudgment, DescriptionPolicy, ModelDescription, OwnerModelLine,
        SeatBirth, SeatSettings, VerdictPayload,
    };
    struct Judge;
    impl DescriptionJudge for Judge {
        fn judge(
            &self,
            _: &str,
            _: &ModelId,
            _: &str,
            _: oneiron::llm::ReasoningEffort,
        ) -> DescriptionJudgment {
            DescriptionJudgment {
                fitness: 1,
                reason: "fixture".into(),
            }
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let model = ModelId::new("google/gemini-model@r1").unwrap();
    let catalog = LlmCatalogEntry {
        model: model.clone(),
        display_name: "Gemini".into(),
        locality: ModelLocality::ThirdParty,
        context_window_tokens: 8192,
        max_output_tokens: None,
        cost: None,
        capabilities: vec![LlmCapability::JsonResponse],
        metadata: Default::default(),
    };
    vault
        .set_description_policy(&DescriptionPolicy {
            models: vec![ModelDescription {
                model: model.clone(),
                wire: ModelWireFormat::Gemini,
                locality: ModelLocality::ThirdParty,
                owner: Some(OwnerModelLine {
                    model,
                    text: "fixture".into(),
                    expected_quality: 500_000,
                }),
                public_benchmark: None,
                vendor: None,
                effort_ladder: vec![oneiron::llm::ReasoningEffort::None],
            }],
            contradiction_margin_millionths: 100_000,
            vault_effort: None,
            purpose_effort: Default::default(),
            global_effort: None,
        })
        .unwrap();
    let settings = SeatSettings {
        allowed_models: None,
        effort: None,
        inference_overrides: std::collections::BTreeMap::from([
            ("maxOutputTokens".into(), json!(16)),
            ("topP".into(), json!(0.2)),
        ]),
    };
    let tier = TierPrecedence::for_purpose(&CallPurpose::AnswerGen, ModelTierRef("default".into()));
    let seat = vault
        .route_seat(
            SeatBirth {
                id: "gemini-pin",
                role: "writer",
                task: "write",
                purpose: &CallPurpose::AnswerGen,
                settings: &settings,
                tier: &tier,
            },
            &Judge,
        )
        .unwrap();
    let base = LlmRequest {
        model: ModelId::new("google/old-model@r1").unwrap(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::AnswerGen,
            class: CallClass::BestEffort,
            tier,
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: "old user text".into(),
            }],
        }],
        tools: vec![],
        params: std::collections::BTreeMap::from([
            ("max_tokens".into(), json!(4096)),
            ("top_p".into(), json!(0.9)),
            ("maxOutputTokens".into(), json!(8192)),
            ("topP".into(), json!(0.95)),
        ]),
        provider_options: Default::default(),
    };
    let mut generate = base.clone();
    seat.bind(&mut generate).unwrap();
    let wire = super::wire::build_request(&catalog, &generate, false).unwrap();
    assert_eq!(wire.body["generationConfig"]["maxOutputTokens"], json!(16));
    assert_eq!(wire.body["generationConfig"]["topP"], json!(0.2));
    assert!(!generate.params.contains_key("max_tokens"));
    assert!(!generate.params.contains_key("top_p"));

    let mut verdict = base;
    verdict.envelope.response_format = ResponseFormat::Json {
        schema: json!({"type":"object"}),
    };
    let routed = vault
        .routed_verdict_request(
            "schema check",
            &Judge,
            &settings,
            verdict,
            VerdictPayload {
                instructions: Some("current instruction".into()),
                input: vec![ContentPart::Text {
                    text: "current input".into(),
                }],
            },
        )
        .unwrap();
    let wire = super::wire::build_request(&catalog, &routed, false).unwrap();
    assert_eq!(wire.body["generationConfig"]["maxOutputTokens"], json!(16));
    assert_eq!(wire.body["generationConfig"]["topP"], json!(0.2));
    assert_eq!(
        wire.body["systemInstruction"]["parts"][0]["text"],
        json!("current instruction")
    );
    assert_eq!(
        wire.body["contents"][0]["parts"][0]["text"],
        json!("current input")
    );
    assert_eq!(
        wire.body["generationConfig"]["responseMimeType"],
        json!("application/json")
    );
    assert!(vault.routed_seat("gemini-pin").unwrap().is_some());
}

#[test]
fn manifest_gemini_seat_none_clears_stale_thinking_on_recorded_wire() {
    use oneiron::llm::ReasoningEffort;
    use oneiron::llm::manifest::{MODEL_ROLES, ModelBinding, ModelManifest, ModelSlot};
    use oneiron::llm::seat::{
        ModelDescription, SeatCandidate, SeatJudge, SeatJudgment, SeatKind, SeatTask,
    };
    use std::sync::{Arc, Mutex};

    struct Judge(ModelId, Option<ReasoningEffort>);
    impl SeatJudge for Judge {
        fn judge(&self, _: &SeatTask, rows: &[SeatCandidate]) -> oneiron::Result<SeatJudgment> {
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].wire, ModelWireFormat::Gemini);
            assert_eq!(rows[0].default_effort, ReasoningEffort::None);
            Ok(SeatJudgment {
                model: self.0.clone(),
                effort: self.1,
                why: "The owner description fits this task".into(),
            })
        }
    }
    struct Recording(Arc<Mutex<Vec<GeminiHttpRequest>>>);
    impl GeminiTransport for Recording {
        fn execute<'a>(
            &'a self,
            request: GeminiHttpRequest,
            _: &'a BudgetLease,
        ) -> GeminiFuture<'a> {
            self.0.lock().unwrap().push(request);
            Box::pin(async {
                Ok(GeminiHttpResponse {
                    status: 200,
                    body: fixture(),
                })
            })
        }
        fn stream<'a>(
            &'a self,
            _: GeminiHttpRequest,
            _: &'a BudgetLease,
        ) -> LlmResult<GeminiProviderStream<'a>> {
            Err(FatalLlmError::InvalidRequest.into())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let model = ModelId::new("google/gemini-model@r1").unwrap();
    vault
        .set_model_manifest(&ModelManifest {
            version: 2,
            roles: MODEL_ROLES
                .into_iter()
                .map(|role| {
                    (
                        role,
                        ModelBinding {
                            model: model.clone(),
                            slot: ModelSlot::Llm,
                            tier: ModelTierRef("legacy".into()),
                            route_models: BTreeMap::new(),
                        },
                    )
                })
                .collect(),
            routes: [ModelSlot::Llm, ModelSlot::Embedder, ModelSlot::Oneironer]
                .into_iter()
                .map(|slot| (slot, ModelLocality::ThirdParty))
                .collect(),
            verdict: None,
            seat_policy: None,
        })
        .unwrap();
    let row = ModelRegistryRow {
        version: 1,
        wire: ModelWireFormat::Gemini,
        catalog: LlmCatalogEntry {
            model: model.clone(),
            display_name: "Gemini fixture".into(),
            locality: ModelLocality::ThirdParty,
            context_window_tokens: 8192,
            max_output_tokens: Some(1024),
            cost: Some(LlmCatalogCost {
                input_per_million: "1".into(),
                output_per_million: "1".into(),
                cache_read_per_million: None,
                cache_write_per_million: None,
            }),
            capabilities: vec![LlmCapability::Reasoning, LlmCapability::JsonResponse],
            metadata: BTreeMap::new(),
        },
        scores: BTreeMap::new(),
        fetched_at: BTreeMap::new(),
    };
    vault.put_model_registry_row(&row).unwrap();
    vault
        .set_model_description(&ModelDescription {
            model: model.clone(),
            facet: "reasoning".into(),
            owner: Some("Task judgment".into()),
            measured: None,
            benchmarks: None,
            vendor: None,
        })
        .unwrap();
    let task = SeatTask {
        kind: SeatKind::Attempt,
        warm_scope: "gemini-run".into(),
        task: "judge a task".into(),
        purpose: CallPurpose::AnswerGen,
        facet: "reasoning".into(),
        required: vec![LlmCapability::JsonResponse],
        min_context_tokens: 1000,
        locality: ModelLocality::ThirdParty,
        override_model: None,
        override_effort: None,
    };
    let run_id = EntityId::now();
    let seat = vault
        .birth_model_seat(run_id, &task, &Judge(model.clone(), None))
        .unwrap();
    assert_eq!(seat.effort(), ReasoningEffort::None);
    assert_eq!(
        vault.model_seat_receipt(run_id).unwrap().unwrap().effort,
        ReasoningEffort::None
    );
    let mut request = LlmRequest {
        model: model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::AnswerGen,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AnswerGen,
                ModelTierRef("default".into()),
            ),
            response_format: ResponseFormat::Json {
                schema: json!({"type":"object"}),
            },
            locality: ModelLocality::ThirdParty,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: "task".into(),
            }],
        }],
        tools: vec![],
        params: BTreeMap::from([
            ("reasoning_effort".into(), json!("high")),
            ("thinkingConfig".into(), json!({"thinkingBudget":4096})),
            ("temperature".into(), json!(0.2)),
        ]),
        provider_options: BTreeMap::new(),
    };
    seat.bind(&mut request);
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let backend = GeminiBackend::from_registry(&vault, Recording(recorded.clone())).unwrap();
    let guard =
        BudgetGuard::with_reserve_units("gemini-seat", 100, 10, BudgetExhaustionPolicy::Suspend);
    let lease = guard.admit_for_request(&request).unwrap().lease;
    ready(backend.generate(request.clone(), &lease)).unwrap();
    let seen = recorded.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let generation = &seen[0].body["generationConfig"];
    assert_eq!(generation["temperature"], json!(0.2));
    assert!(generation.get("reasoning_effort").is_none());
    assert!(generation.get("thinkingConfig").is_none());
    drop(seen);
    // Gemini's effort mapping is not a universal enum. Neither admission nor
    // the direct adapter door may claim a non-None pin works silently.
    let mut unsupported = task;
    unsupported.warm_scope = "different-run".into();
    unsupported.override_effort = Some(ReasoningEffort::Low);
    assert!(
        vault
            .birth_model_seat(EntityId::now(), &unsupported, &Judge(model.clone(), None))
            .is_err()
    );
    unsupported.override_effort = None;
    assert!(
        vault
            .birth_model_seat(
                EntityId::now(),
                &unsupported,
                &Judge(model, Some(ReasoningEffort::High))
            )
            .is_err()
    );
    request.envelope.seat_effort = Some(ReasoningEffort::Low);
    assert!(matches!(
        super::wire::build_request(&row.catalog, &request, false),
        Err(LlmError::Fatal(FatalLlmError::InvalidRequest))
    ));
    assert_eq!(recorded.lock().unwrap().len(), 1);
}
