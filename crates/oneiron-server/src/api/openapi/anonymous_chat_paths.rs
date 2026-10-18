//! The standalone anonymous-chat routes: their schemas are the verb table's
//! real request and reply/block types, with no retained response or receipt.

use serde_json::{Map, Value, json};

use oneiron::task_verb::sdk::{AgentVerb, input_schema, output_schema};

pub(super) fn merge_anonymous_chat_paths(spec: &mut Value) {
    const VERB: &str = "ai.anonymous_chat";
    let (Some(request), Some(answer)) = (input_schema(VERB), output_schema(VERB)) else {
        return;
    };
    let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    for (path, operation) in [
        ("/v1/ai/anonymous-chat", "anonymous_chat"),
        ("/v1/core/facade/ai.anonymous_chat", "ai_anonymous_chat"),
    ] {
        paths.insert(path.to_owned(), json!({"post": {
            "tags": ["ai"],
            "operationId": operation,
            "summary": AgentVerb::from_name(VERB).map_or("", AgentVerb::description),
            "description": "Requires the caller's core:read credential. Each request is a separate memory-free turn. No transcript, memory, telemetry, invocation replay or receipt is kept; policy notices are ephemeral in both user and model channels.",
            "security": [{"CoreBearer": []}],
            "requestBody": {"required": true, "content": {"application/json": {"schema": request}}},
            "responses": responses(&answer)
        }}));
    }
}

fn responses(answer: &Value) -> Value {
    let headers = json!({
        "Cache-Control": {"schema": {"type": "string", "const": "no-store"}},
        "x-oneiron-receipt-ref": {"schema": {"type": "string", "const": "none; no-record"}}
    });
    let refusal = json!({
        "type": "object",
        "required": ["error"],
        "properties": {"error": {
            "type": "object",
            "required": ["code"],
            "properties": {"code": {"type": "string"}}
        }}
    });
    let mut responses = Map::new();
    responses.insert("200".to_owned(), json!({
        "description": "The typed reply or policy block. Both notice channels are ephemeral; no durable receipt is justified by this explanation.",
        "headers": headers,
        "content": {"application/json": {"schema": answer}}
    }));
    for (status, description) in [
        (
            "400",
            "Malformed input, empty text, a house_mind target with a model, or a plain_model target without one (invalid_anonymous_chat_request).",
        ),
        (
            "409",
            "The anonymous session could not open or the turn failed (anonymous_session_unavailable or anonymous_chat_failed).",
        ),
        (
            "500",
            "The request-local session could not close (anonymous_session_close_failed).",
        ),
        (
            "503",
            "No configured model serves the selected target (anonymous_model_unavailable).",
        ),
    ] {
        responses.insert(
            status.to_owned(),
            json!({
                "description": description,
                "headers": headers,
                "content": {"application/json": {"schema": refusal}}
            }),
        );
    }
    for (status, description) in [
        ("401", "No valid credential."),
        (
            "403",
            "The credential lacks core:read or was revoked during the turn (credential_revoked).",
        ),
    ] {
        responses.insert(
            status.to_owned(),
            json!({
                "description": description,
                "headers": headers,
                "content": {"application/json": {"schema": {"anyOf": [
                    {"$ref": "#/components/schemas/ApiErrorEnvelope"}, refusal
                ]}}}
            }),
        );
    }
    Value::Object(responses)
}
