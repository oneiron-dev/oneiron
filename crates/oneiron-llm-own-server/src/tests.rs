use super::*;
use futures_core::Stream;
use oneiron::llm::LlmCatalogCost;
use oneiron::*;
use serde_json::json;
use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll, Waker},
};
struct Sequence(VecDeque<LlmResult<LlmStreamEvent>>);
impl Stream for Sequence {
    type Item = LlmResult<LlmStreamEvent>;
    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.0.pop_front())
    }
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
            seat_effort: None,
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
