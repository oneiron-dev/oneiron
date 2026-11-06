//! Shared query/body param extractors, hex-id parsing, and small scalar helpers.

use super::json_rejection_error;
use super::query_rejection_error;
use crate::error::ApiError;
use crate::projection::View;
use axum::extract::Query;
use axum::extract::rejection::JsonRejection;
use axum::extract::rejection::QueryRejection;
use axum::http::HeaderMap;
use axum::http::header::CONTENT_TYPE;
use axum::response::Json;
use serde::Deserialize;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use utoipa::IntoParams;
use utoipa::ToSchema;

pub(super) fn query_params<T>(query: Result<Query<T>, QueryRejection>) -> Result<T, ApiError> {
    let Query(params) = query.map_err(query_rejection_error)?;
    Ok(params)
}

pub(super) fn json_payload<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    let Json(payload) = payload.map_err(json_rejection_error)?;
    Ok(payload)
}

pub(super) fn has_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| {
            let media_type = media_type.trim();
            media_type.eq_ignore_ascii_case("application/json")
                || media_type.to_ascii_lowercase().ends_with("+json")
        })
}

// ─── Core API parity routes ─────────────────────────────────────────────────

pub(super) fn parse_optional_entity_id(
    value: Option<&str>,
    field: &'static str,
) -> Result<oneiron::EntityId, ApiError> {
    value.map_or_else(
        || Ok(oneiron::EntityId::now()),
        |value| parse_entity_id_param(value, field),
    )
}

// ─── Turn VAD annotation ─────────────────────────────────────────────────────

pub(super) fn parse_entity_id_param(
    value: &str,
    field: &'static str,
) -> Result<oneiron::EntityId, ApiError> {
    oneiron::EntityId::from_hex(value).map_err(|_| {
        ApiError::bad_request(
            format!("{field} must be a 32-character hex entity id"),
            Some(field),
        )
    })
}

pub(super) fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub(super) fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

// ─── Search Routes ────────────────────────────────────────────────────────────

pub(super) fn default_limit() -> usize {
    10
}

// ─── Entity Routes ────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ViewQuery {
    /// Optional projection view. Entity reads default to `standard`; edge reads default to `summary`.
    #[schema(example = "standard")]
    #[param(example = "standard")]
    pub(super) view: Option<View>,
}

/// Query parameters for a memory timeline read.
#[derive(Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct MemoryTimelineQuery {
    /// Optional projection view. Timeline reads default to `summary`.
    #[schema(example = "summary")]
    #[param(example = "summary")]
    pub(super) view: Option<View>,
    /// Optional caller retrieval filter (FIX 3977): the URL-encoded JSON of
    /// a read filter, as a request body carries it. It only narrows.
    #[serde(default)]
    #[schema(example = "{\"entity_types\":[0]}")]
    #[param(example = "{\"entity_types\":[0]}")]
    pub(super) filter: Option<String>,
}

/// A GET door's `filter` query parameter (FIX 3977): the JSON of a read
/// filter, decoded as a request body's `filter` field is, a malformed one a
/// typed 400 naming `filter`. Absent, the read keeps the caller's floor.
pub(super) fn read_filter_param(
    raw: Option<&str>,
) -> Result<Option<oneiron::memory::ReadFilterInput>, ApiError> {
    raw.map(|raw| {
        serde_json::from_str(raw).map_err(|_| {
            ApiError::bad_request(
                "filter must be the JSON of a retrieval filter",
                Some("filter"),
            )
        })
    })
    .transpose()
}
