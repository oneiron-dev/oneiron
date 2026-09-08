//! Batch-write DTOs, route handler, and entity-put staging.

use super::super::core_engine_error;
use super::super::json_payload;
use super::super::parse_optional_entity_id;
use super::write_shape::CORE_MAX_BATCH_ENTITIES;
use super::write_shape::CoreEntityWriteResponse;
use super::write_shape::core_entity_timestamps;
use super::write_shape::normalize_platform_announcement_body;
use super::write_shape::stage_core_entity_put;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::projection;
use crate::projection::View;
use crate::server::SyncServer;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use oneiron::registry::ENTITY_TYPE_TURN;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::borrow::Cow;
use std::sync::Arc;
use utoipa::ToSchema;

/// One text-index field to write alongside an entity body in a core batch.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct CoreTextField {
    /// Text index field name.
    #[schema(example = "body")]
    pub(crate) field: String,
    /// Text value to index for this field.
    #[schema(example = "blue hallway door")]
    pub(crate) value: String,
}

/// Entity put operation accepted by the canonical core batch route.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": "0123456789abcdef0123456789abcdef",
    "entity_type": 1,
    "occurred_start": 1782357600_u64,
    "occurred_end": 1782357600_u64,
    "learned_at": 1782357635_u64,
    "body": {
        "txt": "I saw a blue hallway door.",
        "spkr": "user",
        "at": 1782357600_u64
    },
    "text": [{ "field": "body", "value": "blue hallway door" }]
}))]
pub(crate) struct CoreBatchEntityInput {
    /// Optional hex entity id. When omitted, the server generates an id.
    #[serde(default)]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    pub(crate) id: Option<String>,
    /// Numeric entity type byte.
    #[serde(rename = "entity_type", alias = "entityType")]
    #[schema(example = 1)]
    pub(crate) entity_type: u8,
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
    #[schema(value_type = Object, example = json!({"txt": "I saw a blue hallway door."}))]
    pub(crate) body: Value,
    /// Optional explicit text index fields. When omitted, top-level string body fields are indexed.
    #[serde(default)]
    pub(crate) text: Option<Vec<CoreTextField>>,
}

/// Core batch request envelope.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "entities": [{
        "entity_type": 1,
        "body": { "txt": "Blue hallway door", "spkr": "user", "at": 1782357600_u64 }
    }]
}))]
pub(crate) struct CoreBatchRequest {
    /// Entity put operations to commit atomically.
    entities: Vec<CoreBatchEntityInput>,
}

/// Entity write summary returned by core write routes.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreBatchEntityResult {
    /// Hex-encoded entity id written by the batch.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    pub(crate) id: String,
    /// Numeric entity type byte.
    #[schema(example = 1)]
    pub(crate) entity_type: u8,
}

/// Core batch response envelope.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreBatchResponse {
    /// Number of entity puts committed.
    #[schema(example = 1)]
    count: usize,
    /// Entity ids written by the batch.
    entities: Vec<CoreBatchEntityResult>,
}

/// Commit a core entity batch.
#[utoipa::path(
    post,
    path = "/v1/core/batch",
    request_body(content = CoreBatchRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Batch committed atomically.", body = CoreBatchResponse, content_type = "application/json"),
        (status = 400, description = "Malformed batch or invalid entity body.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:write.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Batch commit failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_batch(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CoreBatchRequest>, JsonRejection>,
) -> Result<Json<CoreBatchResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let req = json_payload(payload)?;
    if req.entities.len() > CORE_MAX_BATCH_ENTITIES {
        return Err(ApiError::bad_request(
            format!("entities must contain at most {CORE_MAX_BATCH_ENTITIES} entries"),
            Some("entities"),
        )
        .into());
    }

    let mut batch = server.vault.batch();
    let mut entities = Vec::with_capacity(req.entities.len());
    for entity in req.entities {
        let id = parse_optional_entity_id(entity.id.as_deref(), "id")?;
        let timestamps = core_entity_timestamps(
            entity.occurred_start,
            entity.occurred_end,
            entity.learned_at,
        )?;
        batch = stage_core_entity_put(
            batch,
            &id,
            entity.entity_type,
            timestamps,
            &entity.body,
            entity.text.as_deref(),
        )?;
        entities.push(CoreBatchEntityResult {
            id: id.to_hex(),
            entity_type: entity.entity_type,
        });
    }

    batch.commit().map_err(|error| {
        tracing::error!(error = %error, "core batch commit failed");
        core_engine_error("core batch commit failed", error)
    })?;

    Ok(Json(CoreBatchResponse {
        count: entities.len(),
        entities,
    }))
}

pub(crate) struct CoreEntityWriteInput<'a> {
    pub(crate) id: Option<&'a str>,
    pub(crate) entity_type: u8,
    pub(crate) occurred_start: Option<u64>,
    pub(crate) occurred_end: Option<u64>,
    pub(crate) learned_at: Option<u64>,
    pub(crate) body: &'a Value,
    pub(crate) text: Option<&'a [CoreTextField]>,
}

pub(crate) fn write_core_entity(
    vault: &oneiron::Vault,
    input: CoreEntityWriteInput<'_>,
) -> Result<Json<CoreEntityWriteResponse>, EnvelopedApiError> {
    let id = parse_optional_entity_id(input.id, "id")?;
    let timestamps =
        core_entity_timestamps(input.occurred_start, input.occurred_end, input.learned_at)?;
    let batch = stage_core_entity_put(
        vault.batch(),
        &id,
        input.entity_type,
        timestamps,
        input.body,
        input.text,
    )?;
    batch.commit().map_err(|error| {
        tracing::error!(error = %error, entity_type = input.entity_type, "core entity create failed");
        core_engine_error("core entity create failed", error)
    })?;
    let body = core_body_for_write(input.entity_type, input.body);
    let item = projection::project_entity_parts(
        &id,
        input.entity_type,
        timestamps.learned_at,
        &encode_core_body(&body)?,
        View::Full,
    );
    Ok(Json(CoreEntityWriteResponse {
        id: id.to_hex(),
        entity_type: input.entity_type,
        item,
    }))
}

pub(crate) fn project_core_entity(
    vault: &oneiron::Vault,
    id: &oneiron::EntityId,
    view: View,
) -> Result<Json<Value>, EnvelopedApiError> {
    let Some(item) = projection::project_entity(vault, id, view).map_err(|error| {
        tracing::error!(error = %error, id = %id.to_hex(), "core entity read failed");
        core_engine_error("core entity read failed", error)
    })?
    else {
        return Err(ApiError::not_found("entity", Some(&id.to_hex())).into());
    };
    Ok(Json(item))
}

pub(crate) fn encode_core_body(body: &Value) -> Result<Vec<u8>, ApiError> {
    rmp_serde::to_vec_named(body)
        .map_err(|_| ApiError::bad_request("body must be msgpack-encodable JSON", Some("body")))
}

pub(crate) fn core_body_for_write<'a>(entity_type: u8, body: &'a Value) -> Cow<'a, Value> {
    if entity_type != ENTITY_TYPE_TURN {
        return Cow::Borrowed(body);
    }
    normalize_platform_announcement_body(body)
}
