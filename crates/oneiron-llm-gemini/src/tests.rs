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
            ContentPart::Text { text: "B".into() },
            ContentPart::Text { text: "C".into() },
        ]
    );
    let starts: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            LlmStreamEvent::TextStart { part_id } => Some(part_id),
            _ => None,
        })
        .collect();
    assert_eq!(starts.len(), 3);
    assert_eq!(
        starts
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
}
