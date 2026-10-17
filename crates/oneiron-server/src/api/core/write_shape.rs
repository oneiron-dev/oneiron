//! Create-entity DTOs, and the HTTP face of the core write shape the engine
//! owns ([`oneiron::core_write::shape`]): its refusals as 400s naming their
//! field, and a request's text fields as the engine's.

use super::batch::CoreTextField;
use crate::auth::CoreAuth;
use crate::error::ApiError;
use oneiron::core_write::CoreWriteTextField;
use oneiron::core_write::shape::{self, CoreWriteRefusal};
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

pub(crate) use oneiron::core_write::shape::CORE_MAX_BATCH_ENTITIES;
#[cfg(test)]
pub(crate) use oneiron::core_write::shape::{
    PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE, PLATFORM_ANNOUNCEMENT_VOICE,
};

pub(crate) const CORE_MAX_LIST_LIMIT: usize = 1000;

/// Generic core entity create request.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "body": { "name": "Dream session" },
    "text": [{ "field": "name", "value": "Dream session" }]
}))]
pub(crate) struct CoreCreateEntityRequest {
    /// Optional hex entity id. When omitted, the server generates an id.
    #[serde(default)]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    pub(crate) id: Option<String>,
    /// Occurrence start timestamp in Unix seconds. Defaults to `learned_at` or current server time.
    #[serde(default, rename = "occurred_start", alias = "occurredStart")]
    #[schema(example = 1782357600_u64)]
    pub(crate) occurred_start: Option<u64>,
    /// Occurrence end timestamp in Unix seconds. Defaults to `occurred_start`.
    #[serde(default, rename = "occurred_end", alias = "occurredEnd")]
    #[schema(example = 1782357600_u64)]
    pub(crate) occurred_end: Option<u64>,
    /// Learned-at timestamp in Unix seconds. Defaults to current server time.
    #[serde(default, rename = "learned_at", alias = "learnedAt")]
    #[schema(example = 1782357635_u64)]
    pub(crate) learned_at: Option<u64>,
    /// JSON body encoded into the vault's msgpack entity payload.
    #[schema(value_type = Object, example = json!({"name": "Dream session"}))]
    pub(crate) body: Value,
    /// Optional explicit text index fields. When omitted, top-level string body fields are indexed.
    #[serde(default)]
    pub(crate) text: Option<Vec<CoreTextField>>,
}

/// Response from core conversation/turn create routes.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreEntityWriteResponse {
    /// Hex entity id written by the route.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    pub(crate) id: String,
    /// Numeric entity type byte.
    #[schema(example = 1)]
    pub(crate) entity_type: u8,
    /// Projected entity body after write.
    #[schema(value_type = Object)]
    pub(crate) item: Value,
}

pub(crate) type CoreEntityTimestamps = oneiron::core_write::CoreWriteTimes;

/// A core write shape's refusal: a 400 naming its field.
pub(crate) fn core_write_refusal(refusal: CoreWriteRefusal) -> ApiError {
    ApiError::bad_request(refusal.message(), Some(refusal.field()))
}

pub(crate) fn core_entity_timestamps(
    occurred_start: Option<u64>,
    occurred_end: Option<u64>,
    learned_at: Option<u64>,
) -> Result<CoreEntityTimestamps, ApiError> {
    shape::core_write_times(occurred_start, occurred_end, learned_at).map_err(core_write_refusal)
}

pub(crate) fn stage_core_entity_put<'a>(
    batch: oneiron::BatchBuilder<'a>,
    id: &oneiron::EntityId,
    entity_type: u8,
    timestamps: CoreEntityTimestamps,
    body: &Value,
    text: Option<&[CoreTextField]>,
) -> Result<oneiron::BatchBuilder<'a>, ApiError> {
    shape::stage_core_put(
        batch,
        id,
        entity_type,
        timestamps,
        body,
        text.map(text_pairs),
    )
    .map_err(core_write_refusal)
}

/// Commits `batch` as `auth` wrote it. Below owner grade, a put that turns an
/// agent definition back on is refused
/// ([`oneiron::BatchBuilder::commit_below_owner`]).
pub(crate) fn commit_core_batch(
    auth: &CoreAuth,
    batch: oneiron::BatchBuilder<'_>,
) -> oneiron::Result<()> {
    if auth.is_owner_grade() {
        batch.commit()
    } else {
        batch.commit_below_owner()
    }
}

pub(crate) fn core_text_fields(
    text: Option<&[CoreTextField]>,
    body: &Value,
) -> Vec<(String, String)> {
    shape::core_text_pairs(text.map(text_pairs), body)
}

fn text_pairs(text: &[CoreTextField]) -> impl Iterator<Item = (&str, &str)> {
    text.iter()
        .map(|entry| (entry.field.as_str(), entry.value.as_str()))
}

/// A request's text fields as a row input's.
pub(crate) fn core_write_text(text: Option<Vec<CoreTextField>>) -> Option<Vec<CoreWriteTextField>> {
    text.map(|text| {
        text.into_iter()
            .map(|entry| CoreWriteTextField {
                field: entry.field,
                value: entry.value,
            })
            .collect()
    })
}
