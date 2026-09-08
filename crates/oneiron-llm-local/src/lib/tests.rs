//! Fixture runtime plus request-validation and event-stream behavior tests.
use std::pin::Pin;

use oneiron::{
    CallClass, CallEnvelope, CallPurpose, DeterministicFallback, LlmError, LlmToolSpec,
    ModelTierRef, TierPrecedence,
};
use serde_json::json;

use super::*;

#[derive(Clone)]
struct FixtureRuntime {
    metadata: LocalModelMetadata,
    parts: Vec<LocalOutputPart>,
    usage: LlmUsage,
    finish_reason: FinishReason,
}

impl FixtureRuntime {
    fn new(metadata: LocalModelMetadata, parts: Vec<LocalOutputPart>) -> Self {
        Self {
            metadata,
            parts,
            usage: LlmUsage::zero(),
            finish_reason: FinishReason::Stop,
        }
    }

    fn with_finish_reason(mut self, finish_reason: FinishReason) -> Self {
        self.finish_reason = finish_reason;
        self
    }
}

impl LocalLlmRuntime for FixtureRuntime {
    fn metadata(&self) -> &LocalModelMetadata {
        &self.metadata
    }

    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _abort: LocalAbortHandle,
    ) -> LlmResult<LocalGeneration<'a>> {
        Ok(LocalGeneration::from_parts(
            self.parts.clone(),
            self.usage.clone(),
            self.finish_reason.clone(),
        ))
    }
}

#[test]
fn fixture_model_metadata_detects_tool_calling_support() {
    let without_tools = metadata_with(BTreeMap::new());
    let without_entry = without_tools.catalog_entry();
    assert!(without_entry.supports(&LlmCapability::Streaming));
    assert!(!without_entry.supports(&LlmCapability::ToolCalling));

    let mut metadata = BTreeMap::new();
    metadata.insert(
        "tokenizer.chat_template".to_owned(),
        json!("{% if tools %}<tool_call>{{ tool.name }}</tool_call>{% endif %}"),
    );
    let with_tools = metadata_with(metadata);
    let with_entry = with_tools.catalog_entry();

    assert!(with_entry.supports(&LlmCapability::ToolCalling));
    assert!(with_entry.supports(&LlmCapability::ToolResults));
}

#[test]
fn unsupported_tool_calling_request_fails_before_runtime_generation() {
    let backend = LocalLlmBackend::new(FixtureRuntime::new(
        metadata_with(BTreeMap::new()),
        vec![LocalOutputPart::text("unused")],
    ));
    let mut request = sample_request();
    request.tools.push(LlmToolSpec {
        name: "lookup_memory".to_owned(),
        description: "Look up memory".to_owned(),
        input_schema: json!({"type": "object"}),
    });

    let lease = BudgetLease::for_test("lease");
    let error = match backend.stream_with_abort(request, &lease) {
        Ok(_) => panic!("tool requests require detected tool support"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        LlmError::Fatal(FatalLlmError::Unsupported(UnsupportedCapability {
            capability: LlmCapability::ToolCalling,
            ..
        }))
    ));
}

#[test]
fn stream_conforms_to_start_delta_end_and_terminal_done_contract() {
    let backend = LocalLlmBackend::new(
        FixtureRuntime::new(
            metadata_with_tool_support(),
            vec![
                LocalOutputPart::text("hello").with_part_id("text-1"),
                LocalOutputPart::tool_call("call-1", "lookup_memory", json!({"query": "atlas"}))
                    .with_part_id("tool-1"),
            ],
        )
        .with_finish_reason(FinishReason::ToolCalls),
    );

    let events = collect_events(
        backend
            .stream(sample_request(), &BudgetLease::for_test("lease"))
            .unwrap(),
    );

    assert_eq!(
        events,
        vec![
            LlmStreamEvent::TextStart {
                part_id: "text-1".to_owned(),
            },
            LlmStreamEvent::TextDelta {
                part_id: "text-1".to_owned(),
                text: "hello".to_owned(),
            },
            LlmStreamEvent::TextEnd {
                part_id: "text-1".to_owned(),
            },
            LlmStreamEvent::ToolCallStart {
                part_id: "tool-1".to_owned(),
                call_id: "call-1".to_owned(),
                name: "lookup_memory".to_owned(),
            },
            LlmStreamEvent::ToolCallDelta {
                part_id: "tool-1".to_owned(),
                input_fragment: "{\"query\":\"atlas\"}".to_owned(),
            },
            LlmStreamEvent::ToolCallEnd {
                part_id: "tool-1".to_owned(),
                call_id: "call-1".to_owned(),
                name: "lookup_memory".to_owned(),
                input: json!({"query": "atlas"}),
            },
            LlmStreamEvent::Done {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![
                        ContentPart::Text {
                            text: "hello".to_owned(),
                        },
                        ContentPart::ToolCall {
                            call_id: "call-1".to_owned(),
                            name: "lookup_memory".to_owned(),
                            input: json!({"query": "atlas"}),
                        },
                    ],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::ToolCalls,
            },
        ]
    );
}

#[test]
fn abort_mid_generation_returns_cancelled_done_with_partial_message() {
    let backend = LocalLlmBackend::new(FixtureRuntime::new(
        metadata_with_tool_support(),
        vec![
            LocalOutputPart::text("first").with_part_id("text-1"),
            LocalOutputPart::text("second").with_part_id("text-2"),
        ],
    ));

    let lease = BudgetLease::for_test("lease");
    let (mut stream, abort) = backend.stream_with_abort(sample_request(), &lease).unwrap();
    assert_eq!(
        poll_stream_once(&mut stream).unwrap().unwrap(),
        LlmStreamEvent::TextStart {
            part_id: "text-1".to_owned(),
        }
    );
    assert_eq!(
        poll_stream_once(&mut stream).unwrap().unwrap(),
        LlmStreamEvent::TextDelta {
            part_id: "text-1".to_owned(),
            text: "first".to_owned(),
        }
    );
    assert_eq!(
        poll_stream_once(&mut stream).unwrap().unwrap(),
        LlmStreamEvent::TextEnd {
            part_id: "text-1".to_owned(),
        }
    );

    abort.abort();

    assert_eq!(
        poll_stream_once(&mut stream).unwrap().unwrap(),
        LlmStreamEvent::Done {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: "first".to_owned(),
                }],
            },
            usage: LlmUsage::zero(),
            finish_reason: FinishReason::Cancelled,
        }
    );
    assert!(poll_stream_once(&mut stream).is_none());
}

#[test]
fn dropping_unfinished_stream_signals_prompt_abort() {
    let backend = LocalLlmBackend::new(FixtureRuntime::new(
        metadata_with_tool_support(),
        vec![LocalOutputPart::text("unfinished")],
    ));
    let lease = BudgetLease::for_test("lease");
    let (stream, abort) = backend.stream_with_abort(sample_request(), &lease).unwrap();

    drop(stream);

    assert!(abort.is_aborted());
}

fn metadata_with(metadata: BTreeMap<String, JsonValue>) -> LocalModelMetadata {
    LocalModelMetadata::new(
        ModelId::new("local/fixture@2026-07-06").unwrap(),
        "Fixture",
        8192,
    )
    .with_metadata(metadata)
}

fn metadata_with_tool_support() -> LocalModelMetadata {
    let mut metadata = BTreeMap::new();
    metadata.insert("tool_calling".to_owned(), json!(true));
    metadata_with(metadata)
}

fn sample_request() -> LlmRequest {
    LlmRequest {
        model: ModelId::new("local/fixture@2026-07-06").unwrap(),
        envelope: CallEnvelope {
            purpose: CallPurpose::AutoCheck,
            class: CallClass::Durable {
                fallback: DeterministicFallback {
                    name: "fail_closed_to_proposed".to_owned(),
                    config: None,
                },
            },
            tier: TierPrecedence {
                per_call: None,
                vault_policy: Some(ModelTierRef("local".to_owned())),
                purpose_default: Some(ModelTierRef("tiny".to_owned())),
                global_default: ModelTierRef("standard".to_owned()),
            },
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OnDevice,
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

fn collect_events(mut stream: LlmStream<'_>) -> Vec<LlmStreamEvent> {
    let mut events = Vec::new();
    while let Some(event) = poll_stream_once(&mut stream) {
        events.push(event.unwrap());
    }
    events
}

fn poll_stream_once(stream: &mut LlmStream<'_>) -> Option<LlmResult<LlmStreamEvent>> {
    let waker: &std::task::Waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match Pin::new(stream).poll_next(&mut cx) {
        Poll::Ready(item) => item,
        Poll::Pending => panic!("fixture stream should not pend"),
    }
}
