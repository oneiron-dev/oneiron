//! Decoder checks over provider-shaped replies.
use serde_json::json;

/// F14 H122 (Astra, round 7): a Gemini part with text beside a function call
/// decoded as its text alone, a `Stop` the policy classifier took for a
/// finished, tool-free answer: an Allow. A part holds one piece of data, so a
/// second one beside the text fails the decode, buffered and streamed, and so
/// do candidates, a candidate, content or parts of a shape the decoder cannot
/// walk (Astra, rounds 8 and 9).
/// A text part with its thought markers and a lone function call still
/// decode, and so does a final chunk with no content.
#[test]
fn a_function_call_beside_text_never_decodes_as_a_finished_answer() {
    let allow = "{\"violation\":0,\"policy_category\":null}";
    let reply = |part: serde_json::Value| {
        json!({ "candidates": [{
            "content": { "role": "model", "parts": [part] },
            "finishReason": "STOP",
        }] })
    };
    for part in [
        json!({ "text": allow, "functionCall": { "name": "check_policy", "args": {} } }),
        json!({ "text": allow, "functionCall": { "args": {} } }),
        json!({ "text": allow, "executableCode": { "language": "PYTHON", "code": "print(1)" } }),
    ] {
        assert!(
            super::wire::parse_response(reply(part.clone())).is_err(),
            "H122: {part} decoded as a finished, tool-free answer"
        );
        assert!(
            super::stream::GeminiAccumulator::default()
                .push(reply(part.clone()))
                .is_err(),
            "H122: a streamed {part} finished as a tool-free answer"
        );
    }

    // Content of another shape, after text already streamed, is no Stop
    // either: a later chunk's parts may not be skipped as absent.
    for content in [
        json!({ "role": "model", "parts": { "functionCall": { "name": "check_policy", "args": {} } } }),
        json!({ "role": "model", "parts": "functionCall" }),
        json!([{ "parts": [{ "functionCall": { "name": "check_policy", "args": {} } }] }]),
    ] {
        let mut stream = super::stream::GeminiAccumulator::default();
        stream
            .push(json!({ "candidates": [{ "content": { "role": "model", "parts": [{ "text": allow }] } }] }))
            .expect("the answer's text streams");
        assert!(
            stream
                .push(json!({ "candidates": [{ "content": content, "finishReason": "STOP" }] }))
                .is_err(),
            "H122: a streamed {content} finished the text as a tool-free answer"
        );
    }

    // Nor candidates or a candidate of another shape (Astra, round 9).
    let call = json!({ "role": "model", "parts": [{ "functionCall": { "name": "check_policy", "args": {} } }] });
    for chunk in [
        json!({ "candidates": { "content": call } }),
        json!({ "candidates": [[{ "content": call }]] }),
    ] {
        let mut stream = super::stream::GeminiAccumulator::default();
        stream
            .push(json!({ "candidates": [{ "content": { "role": "model", "parts": [{ "text": allow }] } }] }))
            .expect("the answer's text streams");
        assert!(
            stream.push(chunk.clone()).is_err(),
            "H122: a streamed {chunk} left the text a tool-free answer"
        );
    }

    // The controls.
    let answer = super::wire::parse_response(reply(
        json!({ "text": allow, "thoughtSignature": "signature" }),
    ))
    .expect("a text part decodes");
    assert_eq!(answer.finish_reason, oneiron::FinishReason::Stop);
    let called = super::wire::parse_response(reply(
        json!({ "functionCall": { "name": "check_policy", "args": {} } }),
    ))
    .expect("a lone function call decodes");
    assert_eq!(called.finish_reason, oneiron::FinishReason::ToolCalls);
    let mut stream = super::stream::GeminiAccumulator::default();
    stream
        .push(json!({ "candidates": [{ "content": { "role": "model", "parts": [{ "text": allow }] } }] }))
        .expect("the answer's text streams");
    stream
        .push(json!({ "candidates": [{ "finishReason": "STOP" }] }))
        .expect("a final chunk with no content finishes the answer");
}

/// F12 (H90): a structured-output or tool control that arrives through raw
/// params (which land in `generationConfig`) or provider options needs the
/// capability its typed field would. The typed admission read only the typed
/// fields, so a model without JSON output got a response schema on the wire.
#[test]
fn a_raw_tool_or_format_control_needs_the_capability_its_typed_field_would() {
    use oneiron::llm::{CallClass, CallEnvelope, CallPurpose, ModelTierRef, TierPrecedence};
    use oneiron::{
        ContentPart, FatalLlmError, LlmCapability, LlmCatalogEntry, LlmError, LlmMessage,
        LlmMessageRole, LlmRequest, ModelId, ModelLocality, ResponseFormat,
    };
    use std::collections::BTreeMap;

    const MODEL: &str = "fake/teacher@v1";
    let entry = |capabilities: Vec<LlmCapability>| LlmCatalogEntry {
        model: ModelId::new(MODEL).expect("model"),
        display_name: "teacher".to_owned(),
        locality: ModelLocality::ThirdParty,
        context_window_tokens: 8_192,
        max_output_tokens: None,
        cost: None,
        capabilities,
        metadata: BTreeMap::from([("wire_model".to_owned(), json!("teacher-1"))]),
    };
    let request = || {
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
    };
    let bare = entry(vec![LlmCapability::Streaming]);
    for (via_options, key, value, capability) in [
        (
            false,
            "responseMimeType",
            json!("application/json"),
            LlmCapability::JsonResponse,
        ),
        (
            false,
            "responseSchema",
            json!({ "type": "OBJECT" }),
            LlmCapability::JsonResponse,
        ),
        (
            false,
            "response_json_schema",
            json!({ "type": "object" }),
            LlmCapability::JsonResponse,
        ),
        (
            true,
            "toolConfig",
            json!({ "functionCallingConfig": { "mode": "ANY" } }),
            LlmCapability::ToolCalling,
        ),
        // A cache resource may carry tool declarations the request cannot see.
        (
            true,
            "cachedContent",
            json!("cachedContents/cache-1"),
            LlmCapability::ToolCalling,
        ),
    ] {
        let mut call = request();
        if via_options {
            let mut options = serde_json::Map::new();
            options.insert(key.to_owned(), value.clone());
            call.provider_options
                .insert("gemini".to_owned(), serde_json::Value::Object(options));
        } else {
            call.params.insert(key.to_owned(), value.clone());
        }
        for stream in [false, true] {
            match super::wire::build_request(&bare, &call, stream) {
                Err(LlmError::Fatal(FatalLlmError::Unsupported(refused))) => {
                    assert_eq!(refused.capability, capability, "{key}");
                }
                other => panic!("raw {key} (stream: {stream}) must be refused: {other:?}"),
            }
        }
        let able = entry(vec![LlmCapability::Streaming, capability.clone()]);
        let body = super::wire::build_request(&able, &call, false)
            .expect("a capable model takes the raw control")
            .body;
        let sent = if via_options {
            &body[key]
        } else {
            &body["generationConfig"][key]
        };
        assert_eq!(sent, &value, "{body}");
    }

    let mut call = request();
    call.params.insert("max_tokens".to_owned(), json!(64));
    call.params
        .insert("responseMimeType".to_owned(), json!("text/plain"));
    let body = super::wire::build_request(&bare, &call, false)
        .expect("a sampling field and a plain-text MIME need no capability")
        .body;
    assert_eq!(body["generationConfig"]["maxOutputTokens"], 64, "{body}");
}
