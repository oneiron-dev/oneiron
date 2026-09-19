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
            vec![Ok(GeminiFrame::Chunk(fixture()))].into(),
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
        let lease = guard.admit_for_request(&request).unwrap().lease;
        let generated = ready(backend.generate(request.clone(), &lease)).unwrap();
        assert_eq!(generated.message.content.len(), 3);
        guard.settle_per_call(&lease, &generated.usage).unwrap();
        assert_eq!(guard.read().used_units, 6);
        let lease = guard.admit_for_request(&request).unwrap().lease;
        let mut stream = backend.stream(request, &lease).unwrap();
        let mut events = Vec::new();
        while let Poll::Ready(Some(e)) =
            Pin::new(&mut stream).poll_next(&mut Context::from_waker(Waker::noop()))
        {
            events.push(e.unwrap());
        }
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
