//! The adapter under a run admission's gate: its preflight refuses what its
//! send would, before the call's permit starts.
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use oneiron::llm::run_admission::{
    BudgetLine, CallOutcome, KeyCustody, LeaseUnit, MemoryReceipts, OfferBinding, OfferRoute,
    Payer, RunAdmission, RunCall, RunDeclaration, RunDenied, RunEvent,
};
use oneiron::llm::{
    CallClass, CallEnvelope, CallPurpose, ModelTierRef, ResponseFormat, SingleSend, TierPrecedence,
};
use oneiron::{
    BudgetLease, ContentPart, FatalLlmError, LlmBackend, LlmCatalogEntry, LlmError, LlmMessage,
    LlmMessageRole, LlmRequest, ModelId, ModelLocality,
};
use serde_json::json;

use super::{
    OpenAiCompatBackend, OpenAiCompatConfig, OpenAiCompatFuture, OpenAiCompatHttpRequest,
    OpenAiCompatHttpResponse, OpenAiCompatProviderStream, OpenAiCompatTransport,
    OpenAiCompatTransportError,
};

const MODEL: &str = "fake/teacher@v1";

/// A transport that answers every request once and counts what it sent.
struct OneShot {
    sent: Arc<Mutex<u32>>,
}

impl SingleSend for OneShot {}

impl OpenAiCompatTransport for OneShot {
    fn execute<'a>(
        &'a self,
        _request: OpenAiCompatHttpRequest,
        _lease: &'a BudgetLease,
    ) -> OpenAiCompatFuture<'a> {
        *self.sent.lock().expect("sent") += 1;
        Box::pin(async {
            Ok(OpenAiCompatHttpResponse {
                status: 200,
                headers: BTreeMap::new(),
                body: json!({
                    "choices": [{
                        "message": { "role": "assistant", "content": "ok" },
                        "finish_reason": "stop"
                    }],
                    "usage": { "prompt_tokens": 3, "completion_tokens": 1 }
                }),
            })
        })
    }

    fn stream<'a>(
        &'a self,
        _request: OpenAiCompatHttpRequest,
        _lease: &'a BudgetLease,
    ) -> Result<OpenAiCompatProviderStream<'a>, OpenAiCompatTransportError> {
        Err(OpenAiCompatTransportError::Connection)
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    match std::pin::pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the fake transport answers at once"),
    }
}

fn request() -> LlmRequest {
    let purpose = CallPurpose::Other {
        name: "teacher".to_owned(),
    };
    LlmRequest {
        model: ModelId::new(MODEL).expect("model"),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef("teacher".to_owned())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: "label this pair".to_owned(),
            }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    }
}

#[test]
fn an_option_the_adapter_rejects_is_refused_before_the_permit_starts() {
    let sent = Arc::new(Mutex::new(0));
    let entry = LlmCatalogEntry {
        model: ModelId::new(MODEL).expect("model"),
        display_name: "teacher".to_owned(),
        locality: ModelLocality::ThirdParty,
        context_window_tokens: 8_192,
        max_output_tokens: None,
        cost: None,
        capabilities: Vec::new(),
        metadata: BTreeMap::new(),
    };
    let backend = Arc::new(OpenAiCompatBackend::new(
        OpenAiCompatConfig::from_catalog([entry]),
        OneShot {
            sent: Arc::clone(&sent),
        },
    ));
    let receipts = Arc::new(MemoryReceipts::default());
    let line = BudgetLine {
        limit_units: 20,
        reserve_units: 6,
        unit: LeaseUnit::tokens(),
    };
    let run = RunAdmission::new(
        "run-1",
        RunDeclaration::undeclared(line),
        None,
        receipts.clone(),
    );
    let offer = OfferBinding {
        offer: "teacher@model.test".to_owned(),
        model: ModelId::new(MODEL).expect("model"),
        route: OfferRoute::new("openai", "https://model.test").expect("route"),
        locality: ModelLocality::ThirdParty,
        payer: Payer::CustomerKey,
        credential_binding: Some("customer-key-1".to_owned()),
        catalog_revision: None,
        custody: KeyCustody::T0,
        rates: Vec::new(),
    };
    let gated = run.gate(backend, &offer);
    let mut bad = request();
    bad.provider_options.insert(
        "openai".to_owned(),
        json!({ "parallel_tool_calls": "not-a-boolean" }),
    );
    let permit = run
        .admit(RunCall {
            selector: None,
            request: &bad,
            offer: &offer,
        })
        .expect("permit");
    assert_eq!(
        ready(gated.generate(bad, permit.lease())).map(|_| ()),
        Err(LlmError::Fatal(FatalLlmError::InvalidRequest))
    );
    assert_eq!(*sent.lock().expect("sent"), 0);
    assert!(receipts.rows().iter().any(|row| matches!(
        row.event,
        RunEvent::Denied {
            reason: RunDenied::BackendRefused,
            ..
        }
    )));
    // Unstarted, the permit still carries a call the adapter accepts.
    let response = ready(gated.generate(request(), permit.lease())).expect("answer");
    permit
        .settle(CallOutcome::Answered(&response.usage))
        .expect("settle");
    assert_eq!(*sent.lock().expect("sent"), 1);
    assert_eq!((run.read().used_units, run.read().reserved_units), (4, 0));
}

/// A seat's level reaches an own server where llama.cpp reads it per request
/// (`reasoning_effort`, `chat_template_kwargs`, `reasoning_budget_tokens`; an
/// exllamav3 server renders only the template arguments). A hosted API takes
/// the effort alone: it refuses request fields it does not know.
#[test]
fn an_own_server_gets_the_level_in_its_template_with_the_budget_and_a_hosted_api_the_effort_alone()
{
    for locality in [ModelLocality::OwnServer, ModelLocality::ThirdParty] {
        let config = OpenAiCompatConfig::from_catalog([LlmCatalogEntry {
            model: ModelId::new(MODEL).expect("model"),
            display_name: "teacher".to_owned(),
            locality,
            context_window_tokens: 8_192,
            max_output_tokens: None,
            cost: None,
            capabilities: vec![oneiron::LlmCapability::Reasoning],
            metadata: BTreeMap::new(),
        }]);
        let mut call = request();
        call.envelope.locality = locality;
        call.envelope.seat_effort = Some(oneiron::llm::ReasoningEffort::Medium);
        call.params
            .insert(oneiron::llm::REASONING_BUDGET_PARAM.into(), json!(4_096));
        let body = super::build_openai_chat_request(&config, &call, false)
            .expect("request")
            .body;
        assert_eq!(body["reasoning_effort"], "medium", "{body}");
        if locality == ModelLocality::OwnServer {
            assert_eq!(
                body["chat_template_kwargs"],
                json!({"reasoning_effort": "medium"})
            );
            assert_eq!(body["reasoning_budget_tokens"], 4_096);
        } else {
            assert_eq!(body.get("chat_template_kwargs"), None, "{body}");
            assert_eq!(body.get("reasoning_budget_tokens"), None, "{body}");
        }
    }
}

/// A reply that names no finish is not a finished one. The decoder used to
/// fill in `Stop`, which every caller that demands a finished answer (the
/// policy classifier among them) then read as one.
#[test]
fn a_reply_that_names_no_finish_is_not_a_stop() {
    let answer = json!({ "role": "assistant", "content": "{\"violation\":0}" });
    for choice in [
        json!({ "message": answer }),
        json!({ "message": answer, "finish_reason": null }),
        json!({ "message": answer, "finish_reason": 7 }),
    ] {
        let response = super::parse_openai_chat_response(&json!({ "choices": [choice] }))
            .expect("the reply decodes");
        assert_ne!(
            response.finish_reason,
            oneiron::FinishReason::Stop,
            "{choice}"
        );
    }
    let stopped = super::parse_openai_chat_response(&json!({
        "choices": [{ "message": answer, "finish_reason": "stop" }]
    }))
    .expect("the reply decodes");
    assert_eq!(stopped.finish_reason, oneiron::FinishReason::Stop);
}

/// F14 H122 (Sol, round 7): a tool call this decoder could not read was
/// dropped, and the reply decoded as a `Stop` with only its text, which the
/// policy classifier took for a finished, tool-free answer: an Allow. A reply
/// that asked for a tool is pending, never a verdict, so a malformed
/// `tool_calls` field or entry fails the decode, buffered and streamed. A
/// tool-free answer and a well-formed tool call still decode. The legacy
/// `function_call` field (Astra, round 7) asks for a tool as well, and this
/// adapter offers no legacy functions, so one fails the decode too.
#[test]
fn a_malformed_tool_call_never_decodes_as_a_finished_answer() {
    let allow = "{\"violation\":0,\"policy_category\":null}";
    let buffered = |tool_calls: serde_json::Value| {
        super::parse_openai_chat_response(&json!({ "choices": [{
            "finish_reason": "stop",
            "message": { "role": "assistant", "content": allow, "tool_calls": tool_calls },
        }] }))
    };
    for tool_calls in [
        json!([{ "type": "function", "function": { "name": "check_policy", "arguments": "{}" } }]),
        json!([{ "id": "call-1", "type": "function", "function": { "arguments": "{}" } }]),
        json!([{ "id": "call-1", "type": "function" }]),
        json!(["call-1"]),
        json!({ "id": "call-1", "function": { "name": "check_policy" } }),
        json!("call-1"),
    ] {
        assert!(
            buffered(tool_calls.clone()).is_err(),
            "H122: {tool_calls} decoded as a finished, tool-free answer"
        );
    }
    let streamed = |tool_calls: serde_json::Value| {
        let mut stream = super::stream::OpenAiCompatStreamAccumulator::new();
        stream.push_chunk(json!({
            "choices": [{
                "index": 0,
                "delta": { "content": allow, "tool_calls": tool_calls },
                "finish_reason": "stop",
            }],
            "usage": { "prompt_tokens": 3, "completion_tokens": 1 },
        }))
    };
    for tool_calls in [
        json!([{ "index": 0, "type": "function", "function": { "name": "check_policy", "arguments": "{}" } }]),
        json!([{ "index": 0, "id": "call-1", "type": "function", "function": { "arguments": "{}" } }]),
        json!({ "index": 0, "id": "call-1" }),
        json!("call-1"),
    ] {
        assert!(
            streamed(tool_calls.clone()).is_err(),
            "H122: a streamed {tool_calls} finished as a tool-free answer"
        );
    }

    for function_call in [
        json!({ "name": "check_policy", "arguments": "{}" }),
        json!({ "arguments": "{}" }),
    ] {
        let reply = json!({ "choices": [{
            "finish_reason": "stop",
            "message": { "role": "assistant", "content": allow, "function_call": function_call },
        }] });
        assert!(
            super::parse_openai_chat_response(&reply).is_err(),
            "H122: a legacy {function_call} decoded as a finished, tool-free answer"
        );
        let mut stream = super::stream::OpenAiCompatStreamAccumulator::new();
        let chunk = json!({
            "choices": [{
                "index": 0,
                "delta": { "content": allow, "function_call": function_call },
                "finish_reason": "stop",
            }],
            "usage": { "prompt_tokens": 3, "completion_tokens": 1 },
        });
        assert!(
            stream.push_chunk(chunk).is_err(),
            "H122: a streamed legacy {function_call} finished as a tool-free answer"
        );
    }

    // Choices, a choice or a delta of a shape the stream cannot walk, after
    // text already streamed, are no Stop either (Astra, rounds 8 and 9).
    let call = json!([{ "index": 0, "id": "call-1", "type": "function",
        "function": { "name": "check_policy", "arguments": "{}" } }]);
    for chunk in [
        json!({ "choices": [{ "index": 0, "delta": [{ "tool_calls": call }], "finish_reason": "stop" }] }),
        json!({ "choices": { "0": { "delta": { "tool_calls": call } } } }),
        json!({ "choices": [[{ "index": 0, "delta": { "tool_calls": call } }]] }),
    ] {
        let mut stream = super::stream::OpenAiCompatStreamAccumulator::new();
        stream
            .push_chunk(json!({ "choices": [{ "index": 0, "delta": { "content": allow } }] }))
            .expect("the answer's text streams");
        assert!(
            stream.push_chunk(chunk.clone()).is_err(),
            "H122: a streamed {chunk} left the text a tool-free answer"
        );
    }

    // The controls.
    let answer = buffered(serde_json::Value::Null).expect("a tool-free answer decodes");
    assert_eq!(answer.finish_reason, oneiron::FinishReason::Stop);
    let answer = super::parse_openai_chat_response(&json!({ "choices": [{
        "finish_reason": "stop",
        "message": { "role": "assistant", "content": allow, "function_call": null },
    }] }))
    .expect("a null legacy call is no call");
    assert_eq!(answer.finish_reason, oneiron::FinishReason::Stop);
    let called = buffered(json!([{ "id": "call-1", "type": "function",
        "function": { "name": "check_policy", "arguments": "{}" } }]))
    .expect("a well-formed tool call decodes");
    assert!(
        called
            .message
            .content
            .iter()
            .any(|part| matches!(part, ContentPart::ToolCall { .. }))
    );
    assert!(
        streamed(json!([{ "index": 0, "id": "call-1", "type": "function",
            "function": { "name": "check_policy", "arguments": "{}" } }]))
        .is_ok()
    );
}

/// F12 (H90): a tool or structured-output control that arrives through raw
/// params or provider options needs the capability its typed field would.
/// The typed checks read only the typed fields, so a model without tool
/// calling or JSON output used to get these controls on the wire.
#[test]
fn a_raw_tool_or_format_control_needs_the_capability_its_typed_field_would() {
    use oneiron::LlmCapability;
    let config = |capabilities: Vec<LlmCapability>| {
        OpenAiCompatConfig::from_catalog([LlmCatalogEntry {
            model: ModelId::new(MODEL).expect("model"),
            display_name: "teacher".to_owned(),
            locality: ModelLocality::ThirdParty,
            context_window_tokens: 8_192,
            max_output_tokens: None,
            cost: None,
            capabilities,
            metadata: BTreeMap::new(),
        }])
    };
    let bare = config(vec![LlmCapability::Streaming]);
    for (key, value, capability) in [
        (
            "tools",
            json!([{ "type": "function", "function": { "name": "run" } }]),
            LlmCapability::ToolCalling,
        ),
        ("tool_choice", json!("required"), LlmCapability::ToolCalling),
        (
            "functions",
            json!([{ "name": "run" }]),
            LlmCapability::ToolCalling,
        ),
        (
            "function_call",
            json!({ "name": "run" }),
            LlmCapability::ToolCalling,
        ),
        (
            "parallel_tool_calls",
            json!(true),
            LlmCapability::ToolCalling,
        ),
        (
            "response_format",
            json!({ "type": "json_object" }),
            LlmCapability::JsonResponse,
        ),
        // Own-server spellings of a JSON schema (vLLM, llama.cpp).
        (
            "structured_outputs",
            json!({ "json": { "type": "object" } }),
            LlmCapability::JsonResponse,
        ),
        (
            "guided_json",
            json!({ "type": "object" }),
            LlmCapability::JsonResponse,
        ),
        (
            "json_schema",
            json!({ "type": "object" }),
            LlmCapability::JsonResponse,
        ),
    ] {
        for via_options in [false, true] {
            let mut call = request();
            if via_options {
                let mut options = serde_json::Map::new();
                options.insert(key.to_owned(), value.clone());
                call.provider_options
                    .insert("openai".to_owned(), serde_json::Value::Object(options));
            } else {
                call.params.insert(key.to_owned(), value.clone());
            }
            for stream in [false, true] {
                match super::build_openai_chat_request(&bare, &call, stream) {
                    Err(LlmError::Fatal(FatalLlmError::Unsupported(refused))) => {
                        assert_eq!(refused.capability, capability, "{key}");
                    }
                    other => panic!(
                        "raw {key} (options: {via_options}, stream: {stream}) must be refused: {other:?}"
                    ),
                }
            }
            let able = config(vec![LlmCapability::Streaming, capability.clone()]);
            let body = super::build_openai_chat_request(&able, &call, false)
                .expect("a capable model takes the raw control")
                .body;
            assert_eq!(body[key], value, "{body}");
        }
    }

    let mut call = request();
    call.params.insert("temperature".to_owned(), json!(0.2));
    call.params
        .insert("response_format".to_owned(), json!({ "type": "text" }));
    let body = super::build_openai_chat_request(&bare, &call, false)
        .expect("a sampling field and a text format need no capability")
        .body;
    assert_eq!(body["temperature"], 0.2, "{body}");
}

/// An image transport that answers every request with one canned reply.
struct CannedImage(serde_json::Value);

impl super::OpenAiImageTransport for CannedImage {
    fn execute<'a>(
        &'a self,
        _request: super::OpenAiImageHttpRequest,
        _lease: &'a BudgetLease,
    ) -> super::OpenAiImageTransportFuture<'a> {
        let body = self.0.clone();
        Box::pin(async move {
            Ok(super::OpenAiImageHttpResponse {
                status: 200,
                headers: BTreeMap::new(),
                body,
            })
        })
    }
}

fn generate_from(b64_json: String) -> oneiron::LlmResult<oneiron::llm::image::ImageResponse> {
    use oneiron::llm::image::{ImageBackend, ImageIntent};
    let backend = super::DirectOpenAiImageBackend::new(CannedImage(
        json!({ "created": 1, "data": [{ "b64_json": b64_json }] }),
    ));
    let intent = ImageIntent {
        model: ModelId::new(MODEL).expect("model"),
        instruction: "a lighthouse".to_owned(),
        width: 1024,
        height: 1024,
        params: BTreeMap::new(),
    };
    ready(backend.generate(intent, &BudgetLease::for_test("image")))
}

// F04 H366: a provider reply carrying an image past the 64 MiB ceiling is
// refused from its encoded length, before it is decoded. Main decoded it and
// returned it.
#[test]
fn a_provider_image_past_the_ceiling_is_refused_before_it_is_decoded() {
    use base64::Engine as _;
    const CEILING: usize = 64 << 20;
    let encode = |len: usize| base64::engine::general_purpose::STANDARD.encode(vec![7u8; len]);

    let at_ceiling = generate_from(encode(CEILING)).expect("at the ceiling");
    assert_eq!(at_ceiling.image.bytes.len(), CEILING);
    assert_eq!(at_ceiling.metadata.get("created"), Some(&json!(1)));

    let past = generate_from(encode(CEILING + 1));
    assert_eq!(
        past.map(|reply| reply.image.bytes.len()),
        Err(LlmError::Fatal(FatalLlmError::EmptyResponse))
    );
}
