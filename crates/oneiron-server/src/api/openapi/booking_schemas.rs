//! Booking schema blocks for the OpenAPI doc.

use serde_json::Value;
use serde_json::json;

/// Points one request-body or response content schema at a component.
///
/// `slot` is either `requestBody` or an HTTP status code; both hang a
/// `content` map at the same depth, so one helper serves both.
pub(super) fn bind_schema_ref(
    spec: &mut Value,
    path: &str,
    method: &str,
    slot: &str,
    content_type: &str,
    schema_name: &str,
) {
    let container = if slot == "requestBody" {
        spec.get_mut("paths")
            .and_then(|paths| paths.get_mut(path))
            .and_then(|item| item.get_mut(method))
            .and_then(|operation| operation.get_mut("requestBody"))
    } else {
        spec.get_mut("paths")
            .and_then(|paths| paths.get_mut(path))
            .and_then(|item| item.get_mut(method))
            .and_then(|operation| operation.get_mut("responses"))
            .and_then(|responses| responses.get_mut(slot))
    };
    let Some(schema) = container
        .and_then(|value| value.get_mut("content"))
        .and_then(|content| content.get_mut(content_type))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    schema.insert(
        "schema".to_owned(),
        json!({ "$ref": format!("#/components/schemas/{schema_name}") }),
    );
}

/// The versioned instructions document, exactly as the embedded page fragment
/// carries it.
pub(super) fn booking_instructions_block_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "description": "Versioned machine-readable booking instructions for one page. Carries no credential, grant, private calendar data, owner email, internal identifier, or raw constraint sentence.",
        "required": ["version", "page_token", "event_types", "operations", "constraint_schema_version"],
        "properties": {
            "version": {
                "const": oneiron::booking::agent_api::BOOKING_AGENT_INSTRUCTIONS_VERSION,
                "description": "Instructions document version.",
            },
            "page_token": {
                "description": "Opaque booking page handle. It encodes no internal identifier and resolves only inside the server executor.",
                "type": "string",
                "pattern": "^bkp_[0-9a-f]{32}$",
            },
            "event_types": {
                "description": "Event-type keys this page is configured for, sorted.",
                "type": "array",
                "items": { "type": "string" },
            },
            "operations": {
                "description": "Advertised operations in canonical order: availability, book, reschedule, cancel. Paths are relative and same-origin.",
                "type": "array",
                "minItems": 4,
                "maxItems": 4,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["operation", "method", "path"],
                    "properties": {
                        "operation": {
                            "description": "Advertised operation name.",
                            "enum": crate::mcp::MCP_BOOK_OPERATIONS,
                        },
                        "method": { "description": "HTTP method.", "type": "string" },
                        "path": {
                            "description": "Relative, same-origin path.",
                            "type": "string",
                            "pattern": "^/",
                        },
                    },
                },
            },
            "constraint_schema_version": {
                "const": oneiron::booking::constraint::CONSTRAINT_SCHEMA_VERSION,
                "description": "Version of the normalized constraint object this page accepts.",
            },
        },
    })
}

/// The closed response union.
///
/// Availability projects UTC start/end, rank, and the flex flag and nothing
/// else; mutations project only opaque action tokens. The ONE-1812 disclosure
/// ceiling is the shape of this schema, not a rule applied on top of it.
pub(super) fn booking_operation_response_schema() -> Value {
    let ranked_slot = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["start_utc", "end_utc", "rank"],
        "properties": {
            "start_utc": { "description": "Inclusive UTC slot start.", "type": "integer", "minimum": 0 },
            "end_utc": { "description": "Exclusive UTC slot end.", "type": "integer", "minimum": 0 },
            "rank": { "description": "Oracle rank; higher is more preferred.", "type": "number" },
        },
    });
    let selected_slot = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["start_utc", "end_utc"],
        "properties": {
            "start_utc": { "description": "Inclusive UTC slot start.", "type": "integer", "minimum": 0 },
            "end_utc": { "description": "Exclusive UTC slot end.", "type": "integer", "minimum": 0 },
        },
    });
    let action_token = json!({
        "description": "Opaque action-scoped booking credential.",
        "type": "string",
        "pattern": "^[0-9a-f]{64}$",
    });
    json!({
        "description": "Closed booking operation response union, tagged by `op`.",
        "oneOf": [
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["op", "result"],
                "properties": {
                    "op": { "const": "availability" },
                    "result": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["slots", "flex_used"],
                        "properties": {
                            "slots": { "type": "array", "items": ranked_slot },
                            "flex_used": { "type": "boolean" },
                        },
                    },
                },
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["op", "result"],
                "properties": {
                    "op": { "const": "book" },
                    // One `op`/`result` envelope around one `stage`/`result`
                    // envelope, exactly as the request side nests `op`/`input`
                    // around `stage`/`input`.
                    "result": {
                        "oneOf": [
                            {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["stage", "result"],
                                "properties": {
                                    "stage": { "const": "held" },
                                    "result": {
                                        "type": "object",
                                        "additionalProperties": false,
                                        "required": ["hold_token", "selected_slot", "expires_at"],
                                        "properties": {
                                            "hold_token": action_token,
                                            "selected_slot": selected_slot,
                                            "expires_at": { "description": "Server-capped hold expiry.", "type": "integer", "minimum": 0 },
                                        },
                                    },
                                },
                            },
                            {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["stage", "result"],
                                "properties": {
                                    "stage": { "const": "confirmed" },
                                    "result": {
                                        "type": "object",
                                        "additionalProperties": false,
                                        "required": ["reschedule_token", "cancel_token"],
                                        "properties": {
                                            "reschedule_token": action_token,
                                            "cancel_token": action_token,
                                        },
                                    },
                                },
                            },
                            {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["stage", "result"],
                                "properties": {
                                    "stage": { "const": "slot_taken" },
                                    "result": {
                                        "type": "object",
                                        "additionalProperties": false,
                                        "required": ["alternatives"],
                                        "properties": {
                                            "alternatives": { "type": "array", "items": ranked_slot },
                                        },
                                    },
                                },
                            },
                        ],
                    },
                },
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["op", "result"],
                "properties": {
                    "op": { "const": "reschedule" },
                    "result": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["reschedule_token"],
                        "properties": { "reschedule_token": action_token },
                    },
                },
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["op", "result"],
                "properties": {
                    "op": { "const": "cancel" },
                    "result": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["cancel_token"],
                        "properties": { "cancel_token": action_token },
                    },
                },
            },
        ],
    })
}

pub(crate) fn merge_error_components(spec: &mut Value) {
    let Some(components) = spec.get_mut("components").and_then(Value::as_object_mut) else {
        return;
    };
    let schemas = components
        .entry("schemas")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .expect("OpenAPI schemas must be an object");
    let error_components = crate::error::openapi_error_components();
    let error_components = error_components
        .as_object()
        .expect("error components must be an object");
    for (name, schema) in error_components {
        schemas.insert(name.clone(), schema.clone());
    }
}

pub(crate) fn mark_entity_response_as_binary(spec: &mut Value) {
    if let Some(content) = spec
        .get_mut("paths")
        .and_then(Value::as_object_mut)
        .and_then(|paths| paths.get_mut("/api/entity/{id}"))
        .and_then(Value::as_object_mut)
        .and_then(|path_item| path_item.get_mut("get"))
        .and_then(Value::as_object_mut)
        .and_then(|operation| operation.get_mut("responses"))
        .and_then(Value::as_object_mut)
        .and_then(|responses| responses.get_mut("200"))
        .and_then(Value::as_object_mut)
        .and_then(|response| response.get_mut("content"))
        .and_then(Value::as_object_mut)
        .and_then(|content| content.get_mut("application/octet-stream"))
        .and_then(Value::as_object_mut)
    {
        content.insert(
            "schema".to_owned(),
            json!({
                "type": "string",
                "format": "binary",
            }),
        );
    }
}
