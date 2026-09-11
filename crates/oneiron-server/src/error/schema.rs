//! JSON Schema generation for the API error catalog.
//!
//! Split out of `error/mod.rs` (ONE-1979) when two new codes pushed that file
//! over the giant-file bar. Move-only: every name keeps its path through the
//! seam in `mod.rs`.

use serde_json::{Map, Value, json};

use super::ErrorCode;

/// OpenAPI/JSON-schema component for the closed error-code enum.
pub fn error_code_schema() -> Value {
    json!({
        "type": "string",
        "enum": ErrorCode::ALL
            .iter()
            .map(|code| code.as_str())
            .collect::<Vec<_>>(),
    })
}

/// OpenAPI/JSON-schema component for the structured API error body.
pub fn api_error_schema() -> Value {
    json!({
        "type": "object",
        "required": ["code", "message", "details", "suggestions"],
        "additionalProperties": false,
        "properties": {
            "code": error_code_schema(),
            "message": { "type": "string" },
            "details": {
                "oneOf": ErrorCode::ALL
                    .iter()
                    .copied()
                    .map(detail_schema_for_code)
                    .collect::<Vec<_>>(),
                "discriminator": { "propertyName": "code" },
            },
            "suggestions": {
                "type": "array",
                "items": { "type": "string" },
            },
        },
    })
}

/// OpenAPI/JSON-schema component for `/v1/core/*` error envelopes.
pub fn api_error_envelope_schema() -> Value {
    json!({
        "type": "object",
        "required": ["error"],
        "additionalProperties": false,
        "properties": {
            "error": {
                "type": "object",
                "required": ["code", "message", "requestId", "details", "suggestions"],
                "additionalProperties": false,
                "properties": {
                    "code": error_code_schema(),
                    "message": { "type": "string" },
                    "requestId": { "type": "string" },
                    "details": {
                        "oneOf": ErrorCode::ALL
                            .iter()
                            .copied()
                            .map(detail_schema_for_code)
                            .collect::<Vec<_>>(),
                        "discriminator": { "propertyName": "code" },
                    },
                    "suggestions": {
                        "type": "array",
                        "items": { "type": "string" },
                    },
                },
            },
        },
    })
}

/// Reusable OpenAPI components for API error responses.
pub fn openapi_error_components() -> Value {
    json!({
        "ErrorCode": error_code_schema(),
        "ApiError": api_error_schema(),
        "ApiErrorEnvelope": api_error_envelope_schema(),
    })
}

fn detail_schema_for_code(code: ErrorCode) -> Value {
    let mut required = vec!["code"];
    let mut properties = Map::from_iter([("code".to_owned(), json!({ "const": code.as_str() }))]);

    match code {
        ErrorCode::BadRequest => {
            optional_string(&mut properties, "field");
        }
        ErrorCode::Forbidden => {
            optional_string(&mut properties, "requiredScope");
        }
        ErrorCode::NotFound => {
            required.push("resource");
            properties.insert("resource".to_owned(), json!({ "type": "string" }));
            optional_string(&mut properties, "id");
        }
        ErrorCode::StaleEpoch => {
            required.extend(["currentEpoch", "requestedEpoch"]);
            properties.insert("currentEpoch".to_owned(), json!({ "type": "integer" }));
            properties.insert("requestedEpoch".to_owned(), json!({ "type": "integer" }));
        }
        ErrorCode::IdempotencyReplayConflict => {
            optional_string(&mut properties, "idempotencyKey");
        }
        ErrorCode::InvalidState => {
            optional_string(&mut properties, "state");
        }
        ErrorCode::SnapshotMismatch => {
            optional_integer(&mut properties, "expectedEpoch");
            optional_integer(&mut properties, "receivedEpoch");
        }
        ErrorCode::DailyBudgetExhausted => {
            optional_integer(&mut properties, "limit");
            optional_integer(&mut properties, "used");
            optional_string(&mut properties, "resetAt");
        }
        ErrorCode::MirrorNotReady => {
            optional_string(&mut properties, "mirror");
        }
        ErrorCode::UnsupportedFormat => {
            optional_string(&mut properties, "format");
        }
        ErrorCode::NotAcceptable => {
            required.push("accepted");
            properties.insert(
                "accepted".to_owned(),
                json!({ "type": "array", "items": { "type": "string" } }),
            );
        }
        ErrorCode::InvalidHeader => {
            required.push("header");
            properties.insert("header".to_owned(), json!({ "type": "string" }));
        }
        ErrorCode::UnsupportedCapability => {
            required.extend([
                "connector",
                "verb",
                "connectorKnown",
                "supportedConnectors",
                "supportedVerbs",
                "recovery_suggestions",
            ]);
            properties.insert("connector".to_owned(), json!({ "type": "string" }));
            properties.insert("verb".to_owned(), json!({ "type": "string" }));
            properties.insert("connectorKnown".to_owned(), json!({ "type": "boolean" }));
            properties.insert(
                "supportedConnectors".to_owned(),
                json!({ "type": "array", "items": { "type": "string" } }),
            );
            properties.insert(
                "supportedVerbs".to_owned(),
                json!({ "type": "array", "items": { "type": "string" } }),
            );
            properties.insert(
                "recovery_suggestions".to_owned(),
                json!({ "type": "array", "items": { "type": "string" } }),
            );
        }
        ErrorCode::CrdtUnknownTag => {
            optional_integer(&mut properties, "tag");
        }
        ErrorCode::CrdtFrameTooLarge => {
            optional_integer(&mut properties, "maxBytes");
            optional_integer(&mut properties, "receivedBytes");
        }
        ErrorCode::CrdtVersionMismatch => {
            optional_integer(&mut properties, "expectedVersion");
            optional_integer(&mut properties, "receivedVersion");
        }
        ErrorCode::PayloadTooLarge => {
            required.extend(["field", "maxBytes", "receivedBytes"]);
            properties.insert("field".to_owned(), json!({ "type": "string" }));
            properties.insert("maxBytes".to_owned(), json!({ "type": "integer" }));
            properties.insert("receivedBytes".to_owned(), json!({ "type": "integer" }));
        }
        ErrorCode::Unauthorized
        | ErrorCode::NotImplemented
        | ErrorCode::InternalServerError
        | ErrorCode::DeepRetrievalUnavailable
        | ErrorCode::EmbedderUnavailable
        | ErrorCode::CrdtAuthExpired
        | ErrorCode::CrdtDecodeError => {}
    }

    json!({
        "type": "object",
        "required": required,
        "additionalProperties": false,
        "properties": properties,
    })
}

fn optional_string(properties: &mut Map<String, Value>, name: &str) {
    properties.insert(name.to_owned(), json!({ "type": ["string", "null"] }));
}

fn optional_integer(properties: &mut Map<String, Value>, name: &str) {
    properties.insert(name.to_owned(), json!({ "type": ["integer", "null"] }));
}
