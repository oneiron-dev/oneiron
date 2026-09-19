use super::*;
use futures_core::Stream;
use oneiron::llm::LlmCatalogCost;
use oneiron::*;
use serde_json::json;
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
struct Sequence(VecDeque<LlmResult<LlmStreamEvent>>);
impl Stream for Sequence {
    type Item = LlmResult<LlmStreamEvent>;
    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.0.pop_front())
    }
}
struct Transport {
    failure: bool,
}
fn response() -> LlmResponse {
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: "answer".into(),
            }],
        },
        usage: LlmUsage {
            input: LlmInputUsage {
                total: 2,
                ..Default::default()
            },
            output: LlmOutputUsage {
                total: 3,
                text: 3,
                reasoning: 0,
            },
            raw_provider: json!({}),
        },
        finish_reason: FinishReason::Stop,
    }
}
impl OwnServerTransport for Transport {
    fn generate<'a>(&'a self, _: LlmRequest, lease: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        assert!(!lease.id().is_empty());
        Box::pin(async move {
            if self.failure {
                Err(RetryableLlmError::StreamCut.into())
            } else {
                Ok(response())
            }
        })
    }
    fn stream<'a>(&'a self, _: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        assert!(!lease.id().is_empty());
        let r = response();
        let events = if self.failure {
            vec![Err(RetryableLlmError::StreamCut.into())]
        } else {
            vec![
                Ok(LlmStreamEvent::TextStart {
                    part_id: "t".into(),
                }),
                Ok(LlmStreamEvent::TextDelta {
                    part_id: "t".into(),
                    text: "answer".into(),
                }),
                Ok(LlmStreamEvent::TextEnd {
                    part_id: "t".into(),
                }),
                Ok(LlmStreamEvent::Done {
                    message: r.message,
                    usage: r.usage,
                    finish_reason: r.finish_reason,
                }),
            ]
        };
        Ok(LlmStream::new(Sequence(events.into())))
    }
}
#[test]
fn generate_stream_and_failures_use_registry_and_settle_admitted_usage() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let model = ModelId::new("own/model@1").unwrap();
    vault
        .put_model_registry_row(&oneiron::llm::registry::ModelRegistryRow {
            version: 1,
            wire: oneiron::llm::registry::ModelWireFormat::OwnServer,
            catalog: LlmCatalogEntry {
                model: model.clone(),
                display_name: "own".into(),
                locality: ModelLocality::OwnServer,
                context_window_tokens: 8192,
                max_output_tokens: None,
                cost: Some(LlmCatalogCost {
                    input_per_million: "0".into(),
                    output_per_million: "0".into(),
                    cache_read_per_million: None,
                    cache_write_per_million: None,
                }),
                capabilities: vec![LlmCapability::Streaming],
                metadata: BTreeMap::new(),
            },
            scores: BTreeMap::new(),
            fetched_at: BTreeMap::new(),
        })
        .unwrap();
    let request = LlmRequest {
        model,
        envelope: CallEnvelope {
            purpose: CallPurpose::AnswerGen,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AnswerGen,
                ModelTierRef("default".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
        },
        messages: vec![],
        tools: vec![],
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    };
    let backend = OwnServerBackend::from_registry(&vault, Transport { failure: false }).unwrap();
    let guard = BudgetGuard::with_reserve_units("test", 100, 10, BudgetExhaustionPolicy::Suspend);
    let lease = guard.admit_for_request(&request).unwrap().lease;
    let generated = ready(backend.generate(request.clone(), &lease)).unwrap();
    guard.settle_per_call(&lease, &generated.usage).unwrap();
    assert_eq!(guard.read().reserved_units, 0);
    assert_eq!(guard.read().used_units, 5);
    let lease = guard.admit_for_request(&request).unwrap().lease;
    let mut stream = backend.stream(request.clone(), &lease).unwrap();
    let mut terminal = 0;
    while let Poll::Ready(Some(event)) =
        Pin::new(&mut stream).poll_next(&mut Context::from_waker(Waker::noop()))
    {
        if let LlmStreamEvent::Done { usage, .. } = event.unwrap() {
            terminal += 1;
            guard.settle_per_call(&lease, &usage).unwrap();
        }
    }
    assert_eq!(terminal, 1);
    assert_eq!(guard.read().reserved_units, 0);
    assert_eq!(guard.read().used_units, 10);
    let failed = OwnServerBackend::from_registry(&vault, Transport { failure: true }).unwrap();
    let lease = guard.admit_for_request(&request).unwrap().lease;
    assert!(matches!(
        ready(failed.generate(request.clone(), &lease)),
        Err(LlmError::Retryable(_))
    ));
    let mut cut = failed.stream(request, &lease).unwrap();
    assert!(matches!(
        Pin::new(&mut cut).poll_next(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Err(LlmError::Retryable(_))))
    ));
    drop(cut);
    guard.abort(&lease).unwrap();
    assert_eq!(guard.read().reserved_units, 0);
    assert!(matches!(
        oneiron_remote::llm::classify_status(402, &json!({})),
        LlmError::BudgetDenied(_)
    ));
    assert!(matches!(
        oneiron_remote::llm::classify_status(401, &json!({})),
        LlmError::Fatal(_)
    ));
}
