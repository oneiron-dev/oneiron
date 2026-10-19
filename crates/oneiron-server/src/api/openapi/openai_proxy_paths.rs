//! The OpenAI-compatible memory proxy publishes the verb table's exact DTOs.
use serde_json::{Value, json};
use oneiron::task_verb::sdk::{input_schema, output_schema};

pub(super) fn merge_openai_proxy_paths(spec: &mut Value) {
    let (Some(request), Some(answer)) = (
        input_schema("ai.chat.completions"), output_schema("ai.chat.completions"),
    ) else { return; };
    let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) else { return; };
    let refusal = json!({"type": "object", "required": ["error"], "properties": {
        "error": {"type": "object", "required": ["message", "type", "param", "code"],
            "properties": {
                "message": {"type": "string"}, "type": {"type": "string"},
                "param": {"type": "null"}, "code": {"type": "string"}
            }}
    }});
    let mut responses = serde_json::Map::new();
    responses.insert("200".to_owned(), json!({
        "description": "The buffered model reply, usage and memory-injection/proposal outcome.",
        "content": {"application/json": {"schema": answer}}
    }));
    for (status, description) in [
        ("400", "Unsupported or malformed chat request; streaming and multiple choices are refused."),
        ("401", "A live paired connector credential and its holder proof are required."),
        ("402", "The model call's budget was denied."),
        ("403", "The credential, read/remember grant, connector registration or memory egress was refused."),
        ("404", "The host serves no model by that id or alias."),
        ("429", "The downstream rate or quota was exhausted."),
        ("502", "The downstream model failed."),
        ("503", "Recall or an on-device model was unavailable."),
        ("504", "The downstream model timed out."),
    ] {
        responses.insert(status.to_owned(), json!({"description": description,
            "content": {"application/json": {"schema": refusal}}
        }));
    }
    paths.insert("/v1/chat/completions".to_owned(), json!({"post": {
        "tags": ["ai"], "operationId": "openai_proxy_chat_completions",
        "summary": "Recall, inject, forward and remember under the connector's own scope and ceiling.",
        "security": [{"CoreBearer": []}],
        "parameters": [{"name": "x-oneiron-binding", "in": "header", "required": true,
            "schema": {"type": "string"}, "description": "The paired credential holder's proof."}],
        "requestBody": {"required": true, "content": {"application/json": {"schema": request}}},
        "responses": responses
    }}));
}
