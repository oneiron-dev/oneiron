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
fn fixture() -> (tempfile::TempDir, Vault, LlmRequest) {
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
            scope: Default::default(),
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
    (dir, vault, request)
}

#[test]
fn generate_stream_and_failures_use_registry_and_settle_admitted_usage() {
    let (_dir, vault, request) = fixture();
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

#[test]
fn remote_terminal_variants_are_validated_for_generate_and_stream() {
    struct Returned(LlmResponse);
    impl OwnServerTransport for Returned {
        fn generate<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
            Box::pin(async { Ok(self.0.clone()) })
        }
        fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
            Ok(LlmStream::new(Sequence(
                vec![Ok(LlmStreamEvent::Done {
                    message: self.0.message.clone(),
                    usage: self.0.usage.clone(),
                    finish_reason: self.0.finish_reason.clone(),
                })]
                .into(),
            )))
        }
    }
    let (_dir, vault, request) = fixture();
    let guard =
        BudgetGuard::with_reserve_units("terminal", 100, 10, BudgetExhaustionPolicy::Suspend);
    let lease = guard.admit_for_request(&request).unwrap().lease;
    let mut cases = Vec::new();
    for part in [
        ContentPart::ToolResult {
            call_id: "".into(),
            output: json!({}),
            is_error: false,
        },
        ContentPart::ToolResult {
            call_id: "valid-tool-id".into(),
            output: json!({}),
            is_error: false,
        },
        ContentPart::Image {
            media_type: " ".into(),
            image: ImageContent::Url {
                url: "https://example.invalid/a.png".into(),
            },
        },
        ContentPart::Image {
            media_type: "image/png".into(),
            image: ImageContent::Url { url: " ".into() },
        },
        ContentPart::Image {
            media_type: "image/png".into(),
            image: ImageContent::Base64 { data: "".into() },
        },
        ContentPart::ToolCall {
            call_id: " ".into(),
            name: "tool".into(),
            input: json!({}),
        },
        ContentPart::ToolCall {
            call_id: "id".into(),
            name: " ".into(),
            input: json!({}),
        },
        ContentPart::ToolCall {
            call_id: "id".into(),
            name: "tool".into(),
            input: json!([]),
        },
    ] {
        let mut response = response();
        response.message.content = vec![part];
        cases.push((response, Some(FatalLlmError::InvalidRequest)));
    }
    let mut wrong_role = response();
    wrong_role.message.role = LlmMessageRole::User;
    cases.push((wrong_role, Some(FatalLlmError::InvalidRequest)));
    let mut empty = response();
    empty.message.content = vec![ContentPart::Reasoning {
        text: " \n".into(),
        signature: None,
    }];
    cases.push((empty, Some(FatalLlmError::EmptyResponse)));
    for part in [
        ContentPart::Reasoning {
            text: "reason".into(),
            signature: None,
        },
        ContentPart::Image {
            media_type: "image/png".into(),
            image: ImageContent::Base64 {
                data: "YWJj".into(),
            },
        },
        ContentPart::Image {
            media_type: "image/png".into(),
            image: ImageContent::Url {
                url: "https://example.invalid/a.png".into(),
            },
        },
        ContentPart::ToolCall {
            call_id: "id".into(),
            name: "tool".into(),
            input: json!({}),
        },
    ] {
        let mut response = response();
        response.message.content = vec![part];
        cases.push((response, None));
    }
    let mut cancelled = response();
    cancelled.message.content.clear();
    cancelled.finish_reason = FinishReason::Cancelled;
    cases.push((cancelled, None));
    for (response, error) in cases {
        let backend = OwnServerBackend::from_registry(&vault, Returned(response.clone())).unwrap();
        let generated = ready(backend.generate(request.clone(), &lease));
        let mut stream = backend.stream(request.clone(), &lease).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        let Poll::Ready(Some(streamed)) = Pin::new(&mut stream).poll_next(&mut cx) else {
            panic!("expected terminal result");
        };
        if let Some(error) = error {
            assert_eq!(generated, Err(LlmError::Fatal(error.clone())));
            assert_eq!(streamed, Err(LlmError::Fatal(error)));
        } else {
            assert_eq!(generated, Ok(response.clone()));
            assert_eq!(
                streamed,
                Ok(LlmStreamEvent::Done {
                    message: response.message,
                    usage: response.usage,
                    finish_reason: response.finish_reason
                })
            );
        }
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }
    guard.abort(&lease).unwrap();
}

#[test]
fn malformed_stream_events_are_refused_before_publication() {
    struct Events(Vec<LlmStreamEvent>);
    impl OwnServerTransport for Events {
        fn generate<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
            unreachable!()
        }
        fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
            let terminal = response();
            let mut events: Vec<_> = self.0.iter().cloned().map(Ok).collect();
            events.push(Ok(LlmStreamEvent::Done {
                message: terminal.message,
                usage: terminal.usage,
                finish_reason: terminal.finish_reason,
            }));
            Ok(LlmStream::new(Sequence(events.into())))
        }
    }
    let (_dir, vault, request) = fixture();
    let guard = BudgetGuard::with_reserve_units("events", 100, 10, BudgetExhaustionPolicy::Suspend);
    let lease = guard.admit_for_request(&request).unwrap().lease;
    let tool_start = LlmStreamEvent::ToolCallStart {
        part_id: "t".into(),
        call_id: "call".into(),
        name: "f".into(),
    };
    for events in [
        vec![LlmStreamEvent::ToolCallEnd {
            part_id: "t".into(),
            call_id: "call".into(),
            name: "f".into(),
            input: json!({}),
        }],
        vec![
            tool_start.clone(),
            LlmStreamEvent::ToolCallEnd {
                part_id: "t".into(),
                call_id: "call".into(),
                name: "f".into(),
                input: json!(42),
            },
        ],
        vec![
            tool_start.clone(),
            LlmStreamEvent::ToolCallEnd {
                part_id: "t".into(),
                call_id: "other".into(),
                name: "f".into(),
                input: json!({}),
            },
        ],
        vec![
            tool_start,
            LlmStreamEvent::TextEnd {
                part_id: "t".into(),
            },
        ],
        vec![
            LlmStreamEvent::ImageStart {
                part_id: "i".into(),
                media_type: "image/png".into(),
            },
            LlmStreamEvent::ImageEnd {
                part_id: "i".into(),
                media_type: "image/png".into(),
                image: ImageContent::Url { url: " ".into() },
            },
        ],
        vec![LlmStreamEvent::ToolResultStart {
            part_id: "r".into(),
            call_id: "call".into(),
        }],
        vec![
            LlmStreamEvent::TextStart {
                part_id: "t".into(),
            },
            LlmStreamEvent::TextStart {
                part_id: "t".into(),
            },
        ],
        vec![LlmStreamEvent::TextDelta {
            part_id: "missing".into(),
            text: "delta".into(),
        }],
    ] {
        let backend = OwnServerBackend::from_registry(&vault, Events(events.clone())).unwrap();
        let mut stream = backend.stream(request.clone(), &lease).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        for expected in &events[..events.len() - 1] {
            assert_eq!(
                Pin::new(&mut stream).poll_next(&mut cx),
                Poll::Ready(Some(Ok(expected.clone())))
            );
        }
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(Err(FatalLlmError::InvalidRequest.into())))
        );
        assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
    }
    let valid = vec![
        LlmStreamEvent::ToolCallStart {
            part_id: "t".into(),
            call_id: "call".into(),
            name: "f".into(),
        },
        LlmStreamEvent::ToolCallDelta {
            part_id: "t".into(),
            input_fragment: "{}".into(),
        },
        LlmStreamEvent::ToolCallEnd {
            part_id: "t".into(),
            call_id: "call".into(),
            name: "f".into(),
            input: json!({}),
        },
        LlmStreamEvent::ImageStart {
            part_id: "i".into(),
            media_type: "image/png".into(),
        },
        LlmStreamEvent::ImageDelta {
            part_id: "i".into(),
            data_fragment: "YWJj".into(),
        },
        LlmStreamEvent::ImageEnd {
            part_id: "i".into(),
            media_type: "image/png".into(),
            image: ImageContent::Base64 {
                data: "YWJj".into(),
            },
        },
    ];
    let backend = OwnServerBackend::from_registry(&vault, Events(valid.clone())).unwrap();
    let mut stream = backend.stream(request.clone(), &lease).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    for expected in valid {
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(Ok(expected)))
        );
    }
    assert!(matches!(
        Pin::new(&mut stream).poll_next(&mut cx),
        Poll::Ready(Some(Ok(LlmStreamEvent::Done { .. })))
    ));
    assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
    drop(stream);
    let unfinished = OwnServerBackend::from_registry(
        &vault,
        Events(vec![LlmStreamEvent::TextStart {
            part_id: "unfinished".into(),
        }]),
    )
    .unwrap();
    let mut stream = unfinished.stream(request, &lease).unwrap();
    assert!(matches!(
        Pin::new(&mut stream).poll_next(&mut cx),
        Poll::Ready(Some(Ok(LlmStreamEvent::TextStart { .. })))
    ));
    assert_eq!(
        Pin::new(&mut stream).poll_next(&mut cx),
        Poll::Ready(Some(Err(FatalLlmError::InvalidRequest.into())))
    );
    assert_eq!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None));
    drop(stream);
    guard.abort(&lease).unwrap();
}
