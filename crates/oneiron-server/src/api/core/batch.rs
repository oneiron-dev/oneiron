//! Batch-write DTOs, route handler, and entity-put staging.

use super::super::DagWriteError;
use super::super::core_engine_error;
use super::super::json_payload;
use super::super::parse_entity_id_param;
use super::write_shape::CORE_MAX_BATCH_ENTITIES;
use super::write_shape::core_entity_timestamps;
use super::write_shape::core_write_refusal;
use super::write_shape::core_write_text;
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
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use oneiron::core_write::{CoreBatchWriteInput, CoreBatchWriteReceipt};
use oneiron::task_verb::sdk::AgentVerb;
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
    headers: HeaderMap,
    extensions: Extensions,
    payload: Result<Json<CoreBatchRequest>, JsonRejection>,
) -> Result<Json<CoreBatchResponse>, DagWriteError> {
    auth.require(CoreScope::Write)?;
    let req = json_payload(payload)?;
    if req.entities.len() > CORE_MAX_BATCH_ENTITIES {
        return Err(ApiError::bad_request(
            format!("entities must contain at most {CORE_MAX_BATCH_ENTITIES} entries"),
            Some("entities"),
        )
        .into());
    }
    // The route's own refusals first; the row mints what the body omits.
    for entity in &req.entities {
        if let Some(id) = &entity.id {
            parse_entity_id_param(id, "id")?;
        }
        core_entity_timestamps(
            entity.occurred_start,
            entity.occurred_end,
            entity.learned_at,
        )?;
    }
    let input = CoreBatchWriteInput {
        entities: req
            .entities
            .into_iter()
            .map(CoreBatchEntityInput::into_row)
            .collect(),
    };
    // OF-181: `vault.batch`, as an action when the credential binds one,
    // else through the row's own door; both commit at the credential's grade.
    let receipt = match super::super::facade::action_routes::rest_action_bound(
        &server, &auth, &headers, &input,
    )? {
        Some(bound) => {
            let row = AgentVerb::VaultBatch;
            let key = super::super::facade::action_routes::rest_action_key(
                &server, &auth, &headers, row,
            )?;
            let output = super::super::facade::action_routes::execute_facade_row(
                &server, headers, extensions, bound, row, &input, key,
            )
            .await?;
            serde_json::from_value::<CoreBatchWriteReceipt>(output)
                .map_err(|_| ApiError::internal_server_error("batch result encoding failed"))?
        }
        None => super::super::facade::host_doors::write_core_batch(&server, &auth, input).await?,
    };

    Ok(Json(CoreBatchResponse {
        count: receipt.count,
        entities: receipt
            .entities
            .into_iter()
            .map(|entity| CoreBatchEntityResult {
                id: entity.id,
                entity_type: entity.entity_type,
            })
            .collect(),
    }))
}

impl CoreBatchEntityInput {
    fn into_row(self) -> oneiron::core_write::CoreBatchEntityInput {
        oneiron::core_write::CoreBatchEntityInput {
            id: self.id,
            entity_type: self.entity_type,
            occurred_start: self.occurred_start,
            occurred_end: self.occurred_end,
            learned_at: self.learned_at,
            body: self.body,
            text: core_write_text(self.text),
        }
    }
}

pub(crate) fn project_core_entity(
    vault: &oneiron::Vault,
    id: &oneiron::EntityId,
    view: View,
) -> Result<Json<Value>, EnvelopedApiError> {
    let Some(item) = projection::project_entity(vault, id, view).map_err(|error| {
        tracing::error!(kind = ?error.kind(), id = %id.to_hex(), "core entity read failed");
        core_engine_error("core entity read failed", error)
    })?
    else {
        return Err(ApiError::not_found("entity", Some(&id.to_hex())).into());
    };
    Ok(Json(item))
}

pub(crate) fn encode_core_body(body: &Value) -> Result<Vec<u8>, ApiError> {
    oneiron::core_write::shape::encode_core_body(body).map_err(core_write_refusal)
}

pub(crate) fn core_body_for_write(entity_type: u8, body: &Value) -> Cow<'_, Value> {
    oneiron::core_write::shape::core_body_for_write(entity_type, body)
}
