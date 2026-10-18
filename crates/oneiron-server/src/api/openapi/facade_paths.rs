//! The facade rows the OpenAPI document publishes (DOOR-115): each row the
//! verb table marks `openapi` is `POST /v1/core/facade/<verb>`, its request
//! the row's own input schema and its answer the row's output schema, both
//! read from the generated row table, so no second list of shapes is kept.
//! A refusal carries the facade's own envelope, at the status the facade maps
//! its code to.

use serde_json::{Map, Value, json};

use oneiron::task_verb::sdk::{AgentVerb, OPENAPI_ROWS, input_schema, output_schema};

/// Adds each published facade row's operation to `spec`'s paths.
pub(super) fn merge_facade_paths(spec: &mut Value) {
    let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    for &verb in OPENAPI_ROWS {
        let (Some(request), Some(answer)) = (input_schema(verb), output_schema(verb)) else {
            continue;
        };
        let mut operation = Map::new();
        operation.insert("tags".to_owned(), json!(["facade"]));
        operation.insert(
            "summary".to_owned(),
            json!(AgentVerb::from_name(verb).map_or("", AgentVerb::description)),
        );
        operation.insert("operationId".to_owned(), json!(verb.replace('.', "_")));
        operation.insert("security".to_owned(), json!([{ "CoreBearer": [] }]));
        operation.insert(
            "requestBody".to_owned(),
            json!({"required": true, "content": {"application/json": {"schema": request}}}),
        );
        operation.insert("responses".to_owned(), responses(answer));
        paths.insert(
            format!("/v1/core/facade/{verb}"),
            json!({ "post": Value::Object(operation) }),
        );
    }
}

/// Each refusal a published row may answer, by the status the facade maps
/// its code to. A request with no valid credential is refused before the
/// facade, in the core envelope.
const REFUSALS: &[(&str, &str)] = &[
    (
        "202",
        "A verb hook holds the call on an ask (`PENDING_ASK`); call again once it is answered.",
    ),
    ("400", "The input is malformed (`BAD_REQUEST`)."),
    (
        "403",
        "The credential lacks the row's scope or authority, or the gate refused or held the write (`FORBIDDEN`).",
    ),
    ("404", "A record the input names does not resolve for the caller (`NOT_FOUND`)."),
    (
        "409",
        "A record the input names is not in a state the row admits, or changed since it was read (`INVALID_STATE`).",
    ),
    ("500", "The call did not finish (`INTERNAL_SERVER_ERROR`)."),
];

/// A published row's answer, and each refusal the facade answers it with.
fn responses(answer: Value) -> Value {
    let mut responses = Map::new();
    responses.insert(
        "200".to_owned(),
        json!({
            "description": "The row's typed answer, as its verb hooks' post chain left it.",
            "content": {"application/json": {"schema": answer}}
        }),
    );
    responses.insert(
        "401".to_owned(),
        json!({
            "description": "The request carries no valid credential.",
            "content": {"application/json": {"schema": {"$ref": CORE_ERROR_ENVELOPE}}}
        }),
    );
    for &(status, description) in REFUSALS {
        responses.insert(
            status.to_owned(),
            json!({
                "description": description,
                "content": {"application/json": {"schema": facade_error_schema()}}
            }),
        );
    }
    Value::Object(responses)
}

/// The core envelope a request without a valid credential is refused in.
const CORE_ERROR_ENVELOPE: &str = "#/components/schemas/ApiErrorEnvelope";

/// The facade's refusal envelope, as `MemoryErrorEnvelopeSchema` mirrors it:
/// `{error: {code, message, requestId, suggestions}}`, with the read's
/// narrowing receipt beside it when a read refused.
fn facade_error_schema() -> Value {
    json!({
        "type": "object",
        "required": ["error"],
        "properties": {
            "error": {
                "type": "object",
                "required": ["code", "message", "requestId", "suggestions"],
                "properties": {
                    "code": {"type": "string", "description": "The stable refusal code."},
                    "message": {"type": "string", "description": "What was refused, in words."},
                    "requestId": {
                        "type": "string",
                        "description": "This refusal's correlation id."
                    },
                    "suggestions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "What to do instead."
                    },
                    "receiptRef": {
                        "type": "string",
                        "description": "The call's lasting receipt (`call:<32hex>`), when it has one."
                    },
                    "retryAfter": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "When to call again, in seconds, when no provider answered."
                    }
                }
            },
            "narrowing": {
                "type": "object",
                "description": "The read's narrowing receipt, when a read refused."
            }
        }
    })
}
