//! Structured HTTP API errors and their schema catalog.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::de;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value, json};

/// Closed catalog of error codes emitted by agent-facing server APIs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum ErrorCode {
    #[serde(rename = "BAD_REQUEST")]
    BadRequest,
    #[serde(rename = "UNAUTHORIZED")]
    Unauthorized,
    #[serde(rename = "NOT_FOUND")]
    NotFound,
    #[serde(rename = "INTERNAL_SERVER_ERROR")]
    InternalServerError,
    #[serde(rename = "STALE_EPOCH")]
    StaleEpoch,
    #[serde(rename = "IDEMPOTENCY_REPLAY_CONFLICT")]
    IdempotencyReplayConflict,
    #[serde(rename = "INVALID_STATE")]
    InvalidState,
    #[serde(rename = "SNAPSHOT_MISMATCH")]
    SnapshotMismatch,
    #[serde(rename = "DAILY_BUDGET_EXHAUSTED")]
    DailyBudgetExhausted,
    #[serde(rename = "MIRROR_NOT_READY")]
    MirrorNotReady,
    #[serde(rename = "UNSUPPORTED_FORMAT")]
    UnsupportedFormat,
    #[serde(rename = "NOT_ACCEPTABLE")]
    NotAcceptable,
    #[serde(rename = "INVALID_HEADER")]
    InvalidHeader,
    #[serde(rename = "4001")]
    CrdtAuthExpired,
    #[serde(rename = "4002")]
    CrdtDecodeError,
    #[serde(rename = "4003")]
    CrdtUnknownTag,
    #[serde(rename = "4004")]
    CrdtFrameTooLarge,
    #[serde(rename = "4005")]
    CrdtBulkDecodeFailure,
    #[serde(rename = "4006")]
    CrdtVersionMismatch,
}

impl ErrorCode {
    /// Canonical catalog order used by schema generation and drift tests.
    pub const ALL: &'static [Self] = &[
        Self::BadRequest,
        Self::Unauthorized,
        Self::NotFound,
        Self::InternalServerError,
        Self::StaleEpoch,
        Self::IdempotencyReplayConflict,
        Self::InvalidState,
        Self::SnapshotMismatch,
        Self::DailyBudgetExhausted,
        Self::MirrorNotReady,
        Self::UnsupportedFormat,
        Self::NotAcceptable,
        Self::InvalidHeader,
        Self::CrdtAuthExpired,
        Self::CrdtDecodeError,
        Self::CrdtUnknownTag,
        Self::CrdtFrameTooLarge,
        Self::CrdtBulkDecodeFailure,
        Self::CrdtVersionMismatch,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "BAD_REQUEST",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::NotFound => "NOT_FOUND",
            Self::InternalServerError => "INTERNAL_SERVER_ERROR",
            Self::StaleEpoch => "STALE_EPOCH",
            Self::IdempotencyReplayConflict => "IDEMPOTENCY_REPLAY_CONFLICT",
            Self::InvalidState => "INVALID_STATE",
            Self::SnapshotMismatch => "SNAPSHOT_MISMATCH",
            Self::DailyBudgetExhausted => "DAILY_BUDGET_EXHAUSTED",
            Self::MirrorNotReady => "MIRROR_NOT_READY",
            Self::UnsupportedFormat => "UNSUPPORTED_FORMAT",
            Self::NotAcceptable => "NOT_ACCEPTABLE",
            Self::InvalidHeader => "INVALID_HEADER",
            Self::CrdtAuthExpired => "4001",
            Self::CrdtDecodeError => "4002",
            Self::CrdtUnknownTag => "4003",
            Self::CrdtFrameTooLarge => "4004",
            Self::CrdtBulkDecodeFailure => "4005",
            Self::CrdtVersionMismatch => "4006",
        }
    }

    pub const fn status(self) -> StatusCode {
        match self {
            Self::BadRequest
            | Self::CrdtDecodeError
            | Self::CrdtUnknownTag
            | Self::CrdtBulkDecodeFailure
            | Self::CrdtVersionMismatch => StatusCode::BAD_REQUEST,
            Self::Unauthorized | Self::CrdtAuthExpired => StatusCode::UNAUTHORIZED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::StaleEpoch
            | Self::IdempotencyReplayConflict
            | Self::InvalidState
            | Self::SnapshotMismatch => StatusCode::CONFLICT,
            Self::DailyBudgetExhausted => StatusCode::TOO_MANY_REQUESTS,
            Self::MirrorNotReady => StatusCode::SERVICE_UNAVAILABLE,
            Self::UnsupportedFormat => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::NotAcceptable => StatusCode::NOT_ACCEPTABLE,
            Self::InvalidHeader => StatusCode::BAD_REQUEST,
            Self::CrdtFrameTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        }
    }
}

/// Details payload for each [`ErrorCode`].
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "code")]
pub enum ApiErrorDetails {
    #[serde(rename = "BAD_REQUEST", rename_all = "camelCase")]
    BadRequest { field: Option<String> },
    #[serde(rename = "UNAUTHORIZED")]
    Unauthorized,
    #[serde(rename = "NOT_FOUND", rename_all = "camelCase")]
    NotFound {
        resource: String,
        id: Option<String>,
    },
    #[serde(rename = "INTERNAL_SERVER_ERROR")]
    InternalServerError,
    #[serde(rename = "STALE_EPOCH", rename_all = "camelCase")]
    StaleEpoch {
        current_epoch: u64,
        requested_epoch: u64,
    },
    #[serde(rename = "IDEMPOTENCY_REPLAY_CONFLICT", rename_all = "camelCase")]
    IdempotencyReplayConflict { idempotency_key: Option<String> },
    #[serde(rename = "INVALID_STATE", rename_all = "camelCase")]
    InvalidState { state: Option<String> },
    #[serde(rename = "SNAPSHOT_MISMATCH", rename_all = "camelCase")]
    SnapshotMismatch {
        expected_epoch: Option<u64>,
        received_epoch: Option<u64>,
    },
    #[serde(rename = "DAILY_BUDGET_EXHAUSTED", rename_all = "camelCase")]
    DailyBudgetExhausted {
        limit: Option<u64>,
        used: Option<u64>,
        reset_at: Option<String>,
    },
    #[serde(rename = "MIRROR_NOT_READY", rename_all = "camelCase")]
    MirrorNotReady { mirror: Option<String> },
    #[serde(rename = "UNSUPPORTED_FORMAT", rename_all = "camelCase")]
    UnsupportedFormat { format: Option<String> },
    #[serde(rename = "NOT_ACCEPTABLE", rename_all = "camelCase")]
    NotAcceptable { accepted: Vec<String> },
    #[serde(rename = "INVALID_HEADER", rename_all = "camelCase")]
    InvalidHeader { header: String },
    #[serde(rename = "4001")]
    CrdtAuthExpired,
    #[serde(rename = "4002")]
    CrdtDecodeError,
    #[serde(rename = "4003", rename_all = "camelCase")]
    CrdtUnknownTag { tag: Option<u8> },
    #[serde(rename = "4004", rename_all = "camelCase")]
    CrdtFrameTooLarge {
        max_bytes: Option<usize>,
        received_bytes: Option<usize>,
    },
    #[serde(rename = "4005")]
    CrdtBulkDecodeFailure,
    #[serde(rename = "4006", rename_all = "camelCase")]
    CrdtVersionMismatch {
        expected_version: Option<u16>,
        received_version: Option<u16>,
    },
}

impl ApiErrorDetails {
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::BadRequest { .. } => ErrorCode::BadRequest,
            Self::Unauthorized => ErrorCode::Unauthorized,
            Self::NotFound { .. } => ErrorCode::NotFound,
            Self::InternalServerError => ErrorCode::InternalServerError,
            Self::StaleEpoch { .. } => ErrorCode::StaleEpoch,
            Self::IdempotencyReplayConflict { .. } => ErrorCode::IdempotencyReplayConflict,
            Self::InvalidState { .. } => ErrorCode::InvalidState,
            Self::SnapshotMismatch { .. } => ErrorCode::SnapshotMismatch,
            Self::DailyBudgetExhausted { .. } => ErrorCode::DailyBudgetExhausted,
            Self::MirrorNotReady { .. } => ErrorCode::MirrorNotReady,
            Self::UnsupportedFormat { .. } => ErrorCode::UnsupportedFormat,
            Self::NotAcceptable { .. } => ErrorCode::NotAcceptable,
            Self::InvalidHeader { .. } => ErrorCode::InvalidHeader,
            Self::CrdtAuthExpired => ErrorCode::CrdtAuthExpired,
            Self::CrdtDecodeError => ErrorCode::CrdtDecodeError,
            Self::CrdtUnknownTag { .. } => ErrorCode::CrdtUnknownTag,
            Self::CrdtFrameTooLarge { .. } => ErrorCode::CrdtFrameTooLarge,
            Self::CrdtBulkDecodeFailure => ErrorCode::CrdtBulkDecodeFailure,
            Self::CrdtVersionMismatch { .. } => ErrorCode::CrdtVersionMismatch,
        }
    }
}

/// Machine-actionable API error body.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ApiError {
    code: ErrorCode,
    message: String,
    details: ApiErrorDetails,
    suggestions: Vec<String>,
}

impl ApiError {
    pub fn new(
        code: ErrorCode,
        message: impl Into<String>,
        details: ApiErrorDetails,
        suggestions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        debug_assert_eq!(code, details.code());
        Self {
            code,
            message: message.into(),
            details,
            suggestions: suggestions.into_iter().map(Into::into).collect(),
        }
    }

    pub fn bad_request(message: impl Into<String>, field: Option<&str>) -> Self {
        Self::new(
            ErrorCode::BadRequest,
            message,
            ApiErrorDetails::BadRequest {
                field: field.map(str::to_owned),
            },
            ["Fix the request shape and retry."],
        )
    }

    pub fn unauthorized() -> Self {
        Self::new(
            ErrorCode::Unauthorized,
            "request is not authorized",
            ApiErrorDetails::Unauthorized,
            ["Send the configured x-oneiron-secret header and retry."],
        )
    }

    pub fn not_found(resource: impl Into<String>, id: Option<&str>) -> Self {
        let resource = resource.into();
        Self::new(
            ErrorCode::NotFound,
            format!("{resource} was not found"),
            ApiErrorDetails::NotFound {
                resource,
                id: id.map(str::to_owned),
            },
            ["Verify the identifier and retry."],
        )
    }

    pub fn internal_server_error(message: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::InternalServerError,
            message,
            ApiErrorDetails::InternalServerError,
            ["Retry later. If the failure repeats, inspect the server logs."],
        )
    }

    pub fn stale_epoch(current_epoch: u64, requested_epoch: u64) -> Self {
        Self::new(
            ErrorCode::StaleEpoch,
            "requested epoch is stale",
            ApiErrorDetails::StaleEpoch {
                current_epoch,
                requested_epoch,
            },
            ["Refresh the resource, merge local changes, then retry."],
        )
    }

    pub fn idempotency_replay_conflict(idempotency_key: Option<&str>) -> Self {
        Self::new(
            ErrorCode::IdempotencyReplayConflict,
            "idempotency key was replayed with a different request",
            ApiErrorDetails::IdempotencyReplayConflict {
                idempotency_key: idempotency_key.map(str::to_owned),
            },
            ["Reuse the original request body or send a new Idempotency-Key."],
        )
    }

    pub fn invalid_state(state: Option<&str>) -> Self {
        Self::new(
            ErrorCode::InvalidState,
            "request conflicts with the current resource state",
            ApiErrorDetails::InvalidState {
                state: state.map(str::to_owned),
            },
            ["Fetch the current state before retrying the mutation."],
        )
    }

    pub fn snapshot_mismatch(expected_epoch: Option<u64>, received_epoch: Option<u64>) -> Self {
        Self::new(
            ErrorCode::SnapshotMismatch,
            "snapshot does not match the expected epoch",
            ApiErrorDetails::SnapshotMismatch {
                expected_epoch,
                received_epoch,
            },
            ["Fetch a fresh snapshot and retry from that epoch."],
        )
    }

    pub fn invalid_header(header: impl Into<String>) -> Self {
        let header = header.into();
        Self::new(
            ErrorCode::InvalidHeader,
            format!("invalid {header} header"),
            ApiErrorDetails::InvalidHeader { header },
            ["Fix the header value and retry."],
        )
    }

    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn details(&self) -> &ApiErrorDetails {
        &self.details
    }

    pub fn suggestions(&self) -> &[String] {
        &self.suggestions
    }

    pub const fn status(&self) -> StatusCode {
        self.code.status()
    }
}

impl<'de> Deserialize<'de> for ApiError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            code: ErrorCode,
            message: String,
            details: ApiErrorDetails,
            suggestions: Vec<String>,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.code != wire.details.code() {
            return Err(de::Error::custom(format!(
                "ApiError code {} does not match details code {}",
                wire.code.as_str(),
                wire.details.code().as_str()
            )));
        }

        Ok(Self {
            code: wire.code,
            message: wire.message,
            details: wire.details,
            suggestions: wire.suggestions,
        })
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status(), Json(self)).into_response()
    }
}

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

/// Reusable OpenAPI components for API error responses.
pub fn openapi_error_components() -> Value {
    json!({
        "ErrorCode": error_code_schema(),
        "ApiError": api_error_schema(),
    })
}

fn detail_schema_for_code(code: ErrorCode) -> Value {
    let mut required = vec!["code"];
    let mut properties = Map::from_iter([("code".to_owned(), json!({ "const": code.as_str() }))]);

    match code {
        ErrorCode::BadRequest => {
            optional_string(&mut properties, "field");
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
        ErrorCode::Unauthorized
        | ErrorCode::InternalServerError
        | ErrorCode::CrdtAuthExpired
        | ErrorCode::CrdtDecodeError
        | ErrorCode::CrdtBulkDecodeFailure => {}
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_epoch_error_serializes_contract_shape() {
        let body = serde_json::to_value(ApiError::stale_epoch(7, 4)).unwrap();

        assert_eq!(body["code"], "STALE_EPOCH");
        assert_eq!(body["details"]["code"], "STALE_EPOCH");
        assert_eq!(body["details"]["currentEpoch"], 7);
        assert_eq!(body["details"]["requestedEpoch"], 4);
        assert!(
            body["suggestions"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
            "suggestions must be actionable and non-empty"
        );
    }

    #[test]
    fn error_code_round_trips_catalog_literals() {
        for code in ErrorCode::ALL {
            let encoded = serde_json::to_string(code).unwrap();
            assert_eq!(encoded, format!("\"{}\"", code.as_str()));
            let decoded: ErrorCode = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded, *code);
        }

        let literals = ErrorCode::ALL
            .iter()
            .map(|code| code.as_str())
            .collect::<Vec<_>>();
        for required in [
            "STALE_EPOCH",
            "DAILY_BUDGET_EXHAUSTED",
            "NOT_ACCEPTABLE",
            "INVALID_HEADER",
            "4001",
            "4002",
            "4003",
            "4004",
            "4005",
        ] {
            assert!(
                literals.contains(&required),
                "missing required error-code catalog literal {required}"
            );
        }
    }

    #[test]
    fn conflict_errors_have_distinct_codes() {
        let stale = ApiError::stale_epoch(7, 4);
        let replay = ApiError::idempotency_replay_conflict(Some("idem-1"));

        assert_eq!(stale.status(), StatusCode::CONFLICT);
        assert_eq!(replay.status(), StatusCode::CONFLICT);
        assert_ne!(stale.code(), replay.code());

        let stale_body = serde_json::to_value(stale).unwrap();
        let replay_body = serde_json::to_value(replay).unwrap();
        assert_ne!(stale_body["code"], replay_body["code"]);
    }

    #[test]
    fn error_code_schema_matches_catalog_exactly() {
        let schema = error_code_schema();
        let enum_values = schema["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>();
        let catalog = ErrorCode::ALL
            .iter()
            .map(|code| code.as_str())
            .collect::<Vec<_>>();

        assert_eq!(enum_values, catalog);
    }

    #[test]
    fn openapi_components_expose_error_code_and_api_error() {
        let components = openapi_error_components();
        assert_eq!(components["ErrorCode"], error_code_schema());
        assert_eq!(components["ApiError"], api_error_schema());
    }

    #[test]
    fn crdt_error_codes_match_protocol_close_code_values() {
        assert_eq!(
            ErrorCode::CrdtAuthExpired.as_str(),
            crate::protocol::close_codes::AUTH_EXPIRED.to_string()
        );
        assert_eq!(
            ErrorCode::CrdtDecodeError.as_str(),
            crate::protocol::close_codes::DECODE_ERROR.to_string()
        );
        assert_eq!(
            ErrorCode::CrdtUnknownTag.as_str(),
            crate::protocol::close_codes::UNKNOWN_TAG.to_string()
        );
        assert_eq!(
            ErrorCode::CrdtFrameTooLarge.as_str(),
            crate::protocol::close_codes::FRAME_TOO_LARGE.to_string()
        );
        assert_eq!(
            ErrorCode::CrdtBulkDecodeFailure.as_str(),
            crate::protocol::close_codes::BULK_DECODE_FAILURE.to_string()
        );
        assert_eq!(
            ErrorCode::CrdtVersionMismatch.as_str(),
            crate::protocol::close_codes::VERSION_MISMATCH.to_string()
        );
    }
}
