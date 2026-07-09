use super::SearchResponse;
use super::core_engine_error;
use super::default_limit;
use super::json_payload;
use super::parse_entity_id_param;
use super::parse_optional_entity_id;
use super::scoped_read_for_core_auth;
use super::search_fetch_limit;
use super::search_meta;
use super::search_response;
use super::unix_seconds_now;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorDetails;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::projection;
use crate::projection::View;
use crate::protocol::CountMode;
use crate::protocol::PaginatedResponse;
use crate::protocol::ResponseMeta;
use crate::server::SyncServer;
use axum::extract::Path;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use oneiron::registry::ENTITY_TYPE_TURN;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::borrow::Cow;
use std::sync::Arc;
use utoipa::IntoParams;
use utoipa::ToSchema;

pub(crate) const CORE_MAX_BATCH_ENTITIES: usize = 256;

pub(crate) const CORE_MAX_LIST_LIMIT: usize = 1000;

pub(crate) const PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE: &str = "platform_announcement";

pub(crate) const PLATFORM_ANNOUNCEMENT_VOICE: &str = "platform";

pub(crate) const ANNOUNCEMENT_STATUS_ACTIVE: &str = "active";

pub(crate) const ANNOUNCEMENT_STATUS_CORRECTED: &str = "corrected";

pub(crate) const ANNOUNCEMENT_STATUS_RETRACTED: &str = "retracted";

/// One text-index field to write alongside an entity body in a core batch.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct CoreTextField {
    /// Text index field name.
    #[schema(example = "body")]
    field: String,
    /// Text value to index for this field.
    #[schema(example = "blue hallway door")]
    value: String,
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

/// Unified core query request over existing text/vector retrieval APIs.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "query": "blue hallway",
    "query_vector": [0.1, 0.2, 0.3, 0.4],
    "limit": 10,
    "view": "summary",
    "countMode": "estimate"
}))]
pub(crate) struct CoreQueryRequest {
    /// Optional BM25 text query.
    #[serde(default)]
    #[schema(example = "blue hallway")]
    query: Option<String>,
    /// Optional vector query. If supplied with `query`, the retrieval pipeline combines signals.
    #[serde(default, rename = "query_vector", alias = "queryVector")]
    #[schema(example = json!([0.1, 0.2, 0.3, 0.4]))]
    query_vector: Option<Vec<f32>>,
    /// Maximum result count.
    #[serde(default = "default_limit")]
    #[schema(default = default_limit, example = 10)]
    limit: usize,
    /// Projection view for returned entities. Defaults to summary.
    #[serde(default)]
    #[schema(example = "summary")]
    view: Option<View>,
    /// Count precision for response metadata. Query defaults to estimate.
    #[serde(
        default = "CountMode::default_estimate",
        rename = "countMode",
        alias = "count_mode"
    )]
    #[schema(example = "estimate")]
    count_mode: CountMode,
}

/// Short-id hydrate request.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "ref": "tn1:a7",
    "view": "full"
}))]
pub(crate) struct CoreHydrateRequest {
    /// Canonical short reference in `shortId:contentHashHex` form.
    #[serde(default, rename = "ref", alias = "short_ref", alias = "shortRef")]
    #[schema(example = "tn1:a7")]
    reference: Option<String>,
    /// Short id without the content hash, accepted when `content_hash` is also supplied.
    #[serde(default, rename = "short_id", alias = "shortId")]
    #[schema(example = "tn1")]
    short_id: Option<String>,
    /// Two-hex-digit content hash, accepted when `short_id` is also supplied.
    #[serde(default, rename = "content_hash", alias = "contentHash")]
    #[schema(example = "a7")]
    content_hash: Option<String>,
    /// Projection view for live entities. Defaults to full.
    #[serde(default)]
    #[schema(example = "full")]
    view: Option<View>,
}

/// Short-id hydrate status.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreHydrateStatus {
    /// The short ref resolved to a live entity payload.
    Live,
    /// The short ref resolved to a deleted shell or dangling short-id row.
    Deleted,
}

/// Short-id hydrate response.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreHydrateResponse {
    /// Hydrate state for the resolved short ref.
    status: CoreHydrateStatus,
    /// Requested short id without content hash.
    #[serde(rename = "short_id")]
    #[schema(example = "tn1")]
    short_id: String,
    /// Requested content hash as two lowercase hex digits.
    #[serde(rename = "content_hash")]
    #[schema(example = "a7")]
    content_hash: String,
    /// Hex entity id when the short ref resolves.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: Option<String>,
    /// Numeric entity type byte when the entity header is still present.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 1)]
    entity_type: Option<u8>,
    /// Explicit deletion metadata for deleted refs.
    #[serde(skip_serializing_if = "Option::is_none")]
    deletion: Option<CoreHydrateDeletionMetadata>,
    /// Projected live entity. Omitted for deleted refs.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    item: Option<Value>,
}

/// Deletion metadata returned for a deleted short-id hydrate result.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreHydrateDeletionMetadata {
    /// Storage evidence that proved deletion.
    source: CoreHydrateDeletionSource,
    /// Decoded tombstone reason, absent for legacy/malformed/dangling rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<CoreHydrateDeletionReason>,
    /// Unix seconds from tombstone metadata when available.
    #[serde(skip_serializing_if = "Option::is_none", rename = "deleted_at")]
    #[schema(example = 1771027200_u64)]
    deleted_at: Option<u64>,
    /// Deletion request UUID when the v2 tombstone carried one.
    #[serde(skip_serializing_if = "Option::is_none", rename = "request_id")]
    #[schema(example = "00000000-0000-0000-0000-000000000000")]
    request_id: Option<String>,
    /// Whether the tombstone effect class is destructive/hard.
    hard: bool,
}

/// Source of deletion evidence for short-id hydrate.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreHydrateDeletionSource {
    Tombstone,
    PendingTombstone,
    DanglingShortId,
}

/// Decoded short-id hydrate deletion reason.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreHydrateDeletionReason {
    #[serde(rename = "user_delete")]
    User,
    #[serde(rename = "user_hard_delete")]
    UserHard,
    #[serde(rename = "gdpr_delete")]
    Gdpr,
    #[serde(rename = "policy_delete")]
    Policy,
}

/// Batch short-id hydrate request.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "refs": ["tn1:a7", "tn2:ff"],
    "view": "full"
}))]
pub(crate) struct CoreBatchShortIdHydrateRequest {
    /// Canonical short references in `shortId:contentHashHex` form.
    #[serde(
        default,
        rename = "refs",
        alias = "short_refs",
        alias = "shortRefs",
        alias = "short_ids",
        alias = "shortIds"
    )]
    #[schema(example = json!(["tn1:a7", "tn2:ff"]))]
    refs: Vec<String>,
    /// Projection view for live entities. Defaults to full.
    #[serde(default)]
    #[schema(example = "full")]
    view: Option<View>,
}

/// Batch short-id hydrate response.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreBatchShortIdHydrateResponse {
    /// Per-input hydrate result or typed error.
    results: Vec<CoreBatchShortIdHydrateItem>,
}

/// One batch short-id hydrate item.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreBatchShortIdHydrateItem {
    /// Input short ref.
    #[serde(rename = "ref")]
    #[schema(example = "tn1:a7")]
    reference: String,
    /// Stable per-input hydrate outcome discriminator.
    outcome: CoreShortIdHydrateOutcome,
    /// Live or deleted hydrate payload when the input resolves.
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<CoreHydrateResponse>,
    /// Typed per-input error for malformed or not-found refs.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<CoreShortIdHydrateError>,
}

/// Stable per-input short-id hydrate outcome.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreShortIdHydrateOutcome {
    Live,
    Deleted,
    MalformedShortId,
    NotFound,
}

/// Per-input short-id hydrate error.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreShortIdHydrateError {
    /// Stable machine-readable per-item error kind.
    kind: CoreShortIdHydrateErrorKind,
    /// Human-readable error summary.
    message: String,
    /// Request field that failed validation, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,
}

/// Stable per-input short-id hydrate error kind.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreShortIdHydrateErrorKind {
    MalformedShortId,
    NotFound,
}

/// Query parameters for core list endpoints.
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct CoreListQuery {
    /// Maximum number of entities to return.
    #[serde(default = "default_limit")]
    #[schema(default = default_limit, example = 10)]
    #[param(default = 10, example = 10)]
    pub(crate) limit: usize,
    /// Optional exclusive cursor id for entity-type scans.
    #[serde(default)]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    #[param(example = "0123456789abcdef0123456789abcdef")]
    pub(crate) after: Option<String>,
    /// Projection view. Defaults to summary.
    #[serde(default)]
    #[schema(example = "summary")]
    #[param(example = "summary")]
    pub(crate) view: Option<View>,
    /// Count precision for response metadata. List endpoints default to exact.
    #[serde(default, rename = "countMode", alias = "count_mode")]
    #[schema(example = "exact")]
    #[param(example = "exact")]
    pub(crate) count_mode: CountMode,
}

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

/// List all outbound connector capability manifests.
#[utoipa::path(
    get,
    path = "/v1/core/outbound/capabilities",
    responses(
        (status = 200, description = "Outbound connector capability manifests.", body = Vec<Object>, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn list_core_outbound_capabilities(
    auth: CoreAuth,
) -> Result<Json<&'static [oneiron::OutboundCapabilityManifest]>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    Ok(Json(oneiron::outbound_capability_manifests()))
}

/// Fetch one connector capability manifest.
#[utoipa::path(
    get,
    path = "/v1/core/outbound/capabilities/{connector}",
    params(
        (
            "connector" = String,
            Path,
            description = "Stable outbound connector key.",
            example = "slack"
        )
    ),
    responses(
        (status = 200, description = "Connector outbound capability manifest.", body = Object, content_type = "application/json"),
        (status = 400, description = "Connector is not supported; response uses UNSUPPORTED_CAPABILITY.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn get_core_outbound_capability(
    auth: CoreAuth,
    Path(connector): Path<String>,
) -> Result<Json<&'static oneiron::OutboundCapabilityManifest>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let manifest = oneiron::outbound_capability_manifest(&connector).ok_or_else(|| {
        let error = oneiron::unsupported_outbound_connector(&connector);
        outbound_capability_error(&error)
    })?;
    Ok(Json(manifest))
}

/// Fetch one connector verb contract. Unsupported verbs return a typed
/// `UNSUPPORTED_CAPABILITY` error with recovery suggestions.
#[utoipa::path(
    get,
    path = "/v1/core/outbound/capabilities/{connector}/verbs/{verb}",
    params(
        (
            "connector" = String,
            Path,
            description = "Stable outbound connector key.",
            example = "line"
        ),
        (
            "verb" = String,
            Path,
            description = "Requested outbound verb kind.",
            example = "react"
        )
    ),
    responses(
        (status = 200, description = "Outbound verb field contract.", body = Object, content_type = "application/json"),
        (status = 400, description = "Connector or verb is not supported; response uses UNSUPPORTED_CAPABILITY.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn get_core_outbound_verb_contract(
    auth: CoreAuth,
    Path((connector, verb)): Path<(String, String)>,
) -> Result<Json<&'static oneiron::OutboundVerbContract>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    oneiron::outbound_verb_contract(&connector, &verb)
        .map(Json)
        .map_err(|error| outbound_capability_error(error.as_ref()))
        .map_err(Into::into)
}

pub(crate) fn outbound_capability_error(
    error: &oneiron::UnsupportedOutboundCapability,
) -> ApiError {
    ApiError::unsupported_capability(
        error.connector(),
        error.verb().map(str::to_owned),
        error.connector_known(),
        error.supported_connectors().to_vec(),
        error.supported_verbs().to_vec(),
        error.recovery_suggestions().to_vec(),
    )
}

/// Query core memory through text and/or vector retrieval.
#[utoipa::path(
    post,
    path = "/v1/core/query",
    request_body(content = CoreQueryRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Projected query results.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed query request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Query failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_query(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CoreQueryRequest>, JsonRejection>,
) -> Result<Json<SearchResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let req = json_payload(payload)?;
    let query = non_empty_query(req.query.as_deref());
    validate_core_query_seeds(query, req.query_vector.as_deref())?;

    let view = req.view.unwrap_or(View::Summary);
    let count_mode = req.count_mode.for_search_response();
    let fetch_limit = search_fetch_limit(count_mode, req.limit);
    let scoped_read = scoped_read_for_core_auth(&server.vault, &auth)?;
    let results = run_core_query(
        &scoped_read,
        query,
        req.query_vector.as_deref(),
        fetch_limit,
    )
    .map_err(|error| {
        tracing::error!(error = %error, "core query failed");
        core_engine_error("core query failed", error)
    })?;
    let total = results.len();
    let response = search_response(&scoped_read, results, view, req.limit)?;
    let meta = search_meta(count_mode, total);

    Ok(Json(PaginatedResponse::new(response, None, meta)))
}

/// Hydrate an entity by context-pack short reference.
#[utoipa::path(
    post,
    path = "/v1/core/hydrate",
    request_body(content = CoreHydrateRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Short ref resolved to a live or deleted entity.", body = CoreHydrateResponse, content_type = "application/json"),
        (status = 400, description = "Malformed short ref.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Short ref was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Hydrate lookup failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_hydrate(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CoreHydrateRequest>, JsonRejection>,
) -> Result<Json<CoreHydrateResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let req = json_payload(payload)?;
    let (short_id, content_hash) = parse_short_ref_request(&req)?;
    let content_hash_hex = format!("{content_hash:02x}");
    let view = req.view.unwrap_or(View::Full);
    let scoped_read = scoped_read_for_core_auth(&server.vault, &auth)?;
    let Some(response) =
        hydrate_short_id_response(&scoped_read, short_id.clone(), content_hash, view)?
    else {
        return Err(ApiError::not_found(
            "short_id",
            Some(&format!("{short_id}:{content_hash_hex}")),
        )
        .into());
    };

    Ok(Json(response))
}

/// Batch-hydrate entities by context-pack short references.
#[utoipa::path(
    post,
    path = "/v1/core/batch/shortId/hydrate",
    request_body(content = CoreBatchShortIdHydrateRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Short refs hydrated with per-item typed results/errors.", body = CoreBatchShortIdHydrateResponse, content_type = "application/json"),
        (status = 400, description = "Malformed batch request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Hydrate lookup failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_batch_short_id_hydrate(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CoreBatchShortIdHydrateRequest>, JsonRejection>,
) -> Result<Json<CoreBatchShortIdHydrateResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let req = json_payload(payload)?;
    if req.refs.is_empty() {
        return Err(ApiError::bad_request("refs must not be empty", Some("refs")).into());
    }
    if req.refs.len() > CORE_MAX_BATCH_ENTITIES {
        return Err(ApiError::bad_request(
            format!("refs must contain at most {CORE_MAX_BATCH_ENTITIES} entries"),
            Some("refs"),
        )
        .into());
    }

    let view = req.view.unwrap_or(View::Full);
    let scoped_read = scoped_read_for_core_auth(&server.vault, &auth)?;
    let mut results = Vec::with_capacity(req.refs.len());
    for reference in req.refs {
        let item = match parse_short_ref(&reference) {
            Ok((short_id, content_hash)) => {
                match hydrate_short_id_response(&scoped_read, short_id, content_hash, view)? {
                    Some(result) => CoreBatchShortIdHydrateItem {
                        reference,
                        outcome: match result.status {
                            CoreHydrateStatus::Live => CoreShortIdHydrateOutcome::Live,
                            CoreHydrateStatus::Deleted => CoreShortIdHydrateOutcome::Deleted,
                        },
                        result: Some(result),
                        error: None,
                    },
                    None => CoreBatchShortIdHydrateItem {
                        reference,
                        outcome: CoreShortIdHydrateOutcome::NotFound,
                        result: None,
                        error: Some(CoreShortIdHydrateError {
                            kind: CoreShortIdHydrateErrorKind::NotFound,
                            message: "short_id was not found".to_owned(),
                            field: Some("ref".to_owned()),
                        }),
                    },
                }
            }
            Err(error) => CoreBatchShortIdHydrateItem {
                reference,
                outcome: CoreShortIdHydrateOutcome::MalformedShortId,
                result: None,
                error: Some(CoreShortIdHydrateError {
                    kind: CoreShortIdHydrateErrorKind::MalformedShortId,
                    message: error.message().to_owned(),
                    field: match error.details() {
                        ApiErrorDetails::BadRequest { field } => field.clone(),
                        _ => None,
                    },
                }),
            },
        };
        results.push(item);
    }

    Ok(Json(CoreBatchShortIdHydrateResponse { results }))
}

pub(crate) fn hydrate_short_id_response(
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    short_id: String,
    content_hash: u8,
    view: View,
) -> Result<Option<CoreHydrateResponse>, ApiError> {
    let content_hash_hex = format!("{content_hash:02x}");
    let result = scoped_read
        .hydrate_short_id(&short_id, content_hash)
        .map_err(|error| {
            tracing::error!(error = %error, short_id, content_hash = content_hash_hex, "core short hydrate failed");
            core_engine_error("core short hydrate failed", error)
        })?;

    let Some(oneiron::HydratedShortId {
        id,
        entity_type,
        learned_at,
        deletion,
        body,
    }) = result
    else {
        return Ok(None);
    };

    let Some(body) = body else {
        return Ok(Some(CoreHydrateResponse {
            status: CoreHydrateStatus::Deleted,
            short_id,
            content_hash: content_hash_hex,
            id: Some(id.to_hex()),
            entity_type: (entity_type != 0).then_some(entity_type),
            deletion: deletion.map(core_hydrate_deletion_metadata),
            item: None,
        }));
    };

    let item = projection::project_entity_parts(&id, entity_type, learned_at, &body, view);
    Ok(Some(CoreHydrateResponse {
        status: CoreHydrateStatus::Live,
        short_id,
        content_hash: content_hash_hex,
        id: Some(id.to_hex()),
        entity_type: Some(entity_type),
        deletion: None,
        item: Some(item),
    }))
}

pub(crate) fn core_hydrate_deletion_metadata(
    deletion: oneiron::HydratedShortIdDeletion,
) -> CoreHydrateDeletionMetadata {
    CoreHydrateDeletionMetadata {
        source: match deletion.source {
            oneiron::HydratedShortIdDeletionSource::Tombstone => {
                CoreHydrateDeletionSource::Tombstone
            }
            oneiron::HydratedShortIdDeletionSource::PendingTombstone => {
                CoreHydrateDeletionSource::PendingTombstone
            }
            oneiron::HydratedShortIdDeletionSource::DanglingShortId => {
                CoreHydrateDeletionSource::DanglingShortId
            }
        },
        reason: deletion.reason.map(|reason| match reason {
            oneiron::HydratedShortIdDeletionReason::UserDelete => CoreHydrateDeletionReason::User,
            oneiron::HydratedShortIdDeletionReason::UserHardDelete => {
                CoreHydrateDeletionReason::UserHard
            }
            oneiron::HydratedShortIdDeletionReason::GdprDelete => CoreHydrateDeletionReason::Gdpr,
            oneiron::HydratedShortIdDeletionReason::PolicyDelete => {
                CoreHydrateDeletionReason::Policy
            }
        }),
        deleted_at: deletion.deleted_at,
        request_id: deletion.request_id,
        hard: deletion.hard,
    }
}

#[derive(Clone, Copy)]
pub(crate) struct CoreEntityTimestamps {
    pub(crate) occurred: oneiron::TimeRange,
    pub(crate) learned_at: u64,
}

pub(crate) fn core_entity_timestamps(
    occurred_start: Option<u64>,
    occurred_end: Option<u64>,
    learned_at: Option<u64>,
) -> Result<CoreEntityTimestamps, ApiError> {
    let learned_at = learned_at.unwrap_or_else(unix_seconds_now);
    let start = occurred_start.unwrap_or(learned_at);
    let end = occurred_end.unwrap_or(start);
    if start > end {
        return Err(ApiError::bad_request(
            "occurred_start must be less than or equal to occurred_end",
            Some("occurred_start"),
        ));
    }
    Ok(CoreEntityTimestamps {
        occurred: oneiron::TimeRange { start, end },
        learned_at,
    })
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

pub(crate) fn normalize_platform_announcement_body(body: &Value) -> Cow<'_, Value> {
    let Value::Object(object) = body else {
        return Cow::Borrowed(body);
    };
    if !is_platform_announcement_body(object) {
        return Cow::Borrowed(body);
    }

    let mut normalized = object.clone();
    normalized.remove("messageType");
    normalized.remove("originalText");
    normalized.remove("showOriginal");
    normalized.insert(
        "message_type".to_owned(),
        Value::String(PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE.to_owned()),
    );
    normalized.insert(
        "spkr".to_owned(),
        Value::String(PLATFORM_ANNOUNCEMENT_VOICE.to_owned()),
    );
    normalized.insert(
        "speaker".to_owned(),
        Value::String(PLATFORM_ANNOUNCEMENT_VOICE.to_owned()),
    );
    normalized.insert(
        "voice".to_owned(),
        Value::String(PLATFORM_ANNOUNCEMENT_VOICE.to_owned()),
    );
    normalized.insert(
        "attribution".to_owned(),
        Value::String(PLATFORM_ANNOUNCEMENT_VOICE.to_owned()),
    );
    normalized.insert(
        "render_voice".to_owned(),
        Value::String(PLATFORM_ANNOUNCEMENT_VOICE.to_owned()),
    );
    normalized.insert("platform_voice".to_owned(), Value::Bool(true));
    normalized.insert("is_eiri".to_owned(), Value::Bool(false));

    let status = announcement_status(object);
    normalized.insert(
        "announcement_status".to_owned(),
        Value::String(status.to_owned()),
    );
    normalized.insert(
        "retracted".to_owned(),
        Value::Bool(status == ANNOUNCEMENT_STATUS_RETRACTED),
    );
    normalized.insert(
        "corrected".to_owned(),
        Value::Bool(status == ANNOUNCEMENT_STATUS_CORRECTED),
    );

    let original = announcement_original_text(object);
    if let Some(original) = original {
        normalized.insert(
            "original_txt".to_owned(),
            Value::String(original.to_owned()),
        );
    }
    let localized = object_bool_field(object, &["localized"]).unwrap_or(false)
        || object_string_field(object, &["locale", "localized_locale", "localizedLocale"])
            .is_some()
        || original.is_some();
    if localized {
        normalized.insert("localized".to_owned(), Value::Bool(true));
    }
    if let Some(show_original) = object_bool_field(object, &["show_original", "showOriginal"]) {
        normalized.insert("show_original".to_owned(), Value::Bool(show_original));
    } else if original.is_some() {
        normalized.insert("show_original".to_owned(), Value::Bool(true));
    }

    Cow::Owned(Value::Object(normalized))
}

pub(crate) fn is_platform_announcement_body(object: &serde_json::Map<String, Value>) -> bool {
    object_string_field(object, &["message_type", "messageType"]).is_some_and(|message_type| {
        message_type.eq_ignore_ascii_case(PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE)
    })
}

pub(crate) fn announcement_status(object: &serde_json::Map<String, Value>) -> &'static str {
    match object_string_field(object, &["announcement_status", "announcementStatus"]) {
        Some(status) if status.eq_ignore_ascii_case(ANNOUNCEMENT_STATUS_RETRACTED) => {
            ANNOUNCEMENT_STATUS_RETRACTED
        }
        Some(status) if status.eq_ignore_ascii_case(ANNOUNCEMENT_STATUS_CORRECTED) => {
            ANNOUNCEMENT_STATUS_CORRECTED
        }
        Some(status) if status.eq_ignore_ascii_case(ANNOUNCEMENT_STATUS_ACTIVE) => {
            ANNOUNCEMENT_STATUS_ACTIVE
        }
        _ if object_bool_field(object, &["retracted"]).unwrap_or(false) => {
            ANNOUNCEMENT_STATUS_RETRACTED
        }
        _ if object_bool_field(object, &["corrected"]).unwrap_or(false) => {
            ANNOUNCEMENT_STATUS_CORRECTED
        }
        _ => ANNOUNCEMENT_STATUS_ACTIVE,
    }
}

pub(crate) fn announcement_original_text(object: &serde_json::Map<String, Value>) -> Option<&str> {
    object_string_field(object, &["original_txt", "originalText", "original_text"]).or_else(|| {
        let original = object.get("original")?.as_object()?;
        object_string_field(original, &["txt", "text", "body"])
    })
}

pub(crate) fn object_string_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
}

pub(crate) fn object_bool_field(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<bool> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_bool))
}

pub(crate) fn stage_core_entity_put<'a>(
    batch: oneiron::BatchBuilder<'a>,
    id: &oneiron::EntityId,
    entity_type: u8,
    timestamps: CoreEntityTimestamps,
    body: &Value,
    text: Option<&[CoreTextField]>,
) -> Result<oneiron::BatchBuilder<'a>, ApiError> {
    let body = core_body_for_write(entity_type, body);
    let data = encode_core_body(&body)?;
    let mut batch = batch.put(
        id,
        entity_type,
        timestamps.occurred,
        timestamps.learned_at,
        &data,
    );
    let text_fields = core_text_fields(text, &body);
    if !text_fields.is_empty() {
        let refs: Vec<(&str, &str)> = text_fields
            .iter()
            .map(|(field, value)| (field.as_str(), value.as_str()))
            .collect();
        batch = batch.text(id, &refs);
    }
    Ok(batch)
}

pub(crate) fn core_text_fields(
    text: Option<&[CoreTextField]>,
    body: &Value,
) -> Vec<(String, String)> {
    if let Some(text) = text {
        return text
            .iter()
            .filter(|entry| !entry.field.is_empty() && !entry.value.is_empty())
            .map(|entry| (entry.field.clone(), entry.value.clone()))
            .collect();
    }

    let Value::Object(object) = body else {
        return Vec::new();
    };
    object
        .iter()
        .filter_map(|(key, value)| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(|value| (key.clone(), value.to_owned()))
        })
        .collect()
}

pub(crate) fn non_empty_query(query: Option<&str>) -> Option<&str> {
    query.map(str::trim).filter(|query| !query.is_empty())
}

pub(crate) fn validate_core_query_seeds(
    query: Option<&str>,
    vector: Option<&[f32]>,
) -> Result<(), ApiError> {
    if non_empty_query(query).is_none() && vector.is_none() {
        return Err(ApiError::bad_request(
            "query or query_vector is required",
            Some("query"),
        ));
    }
    if vector.is_some_and(|vector| vector.iter().any(|value| !value.is_finite())) {
        return Err(ApiError::bad_request(
            "query_vector values must be finite",
            Some("query_vector"),
        ));
    }
    Ok(())
}

pub(crate) fn run_core_query(
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    query: Option<&str>,
    vector: Option<&[f32]>,
    limit: usize,
) -> oneiron::Result<Vec<oneiron::ScoredEntity>> {
    match (query, vector) {
        (Some(query), Some(vector)) => scoped_read.search(query, vector, limit),
        (Some(query), None) => scoped_read.search_text(query, limit),
        (None, Some(vector)) => scoped_read.search_vector(vector, limit),
        (None, None) => Ok(Vec::new()),
    }
}

pub(crate) fn parse_short_ref_request(req: &CoreHydrateRequest) -> Result<(String, u8), ApiError> {
    if let Some(reference) = req.reference.as_deref() {
        return parse_short_ref(reference);
    }
    let Some(short_id) = req.short_id.as_deref() else {
        return Err(ApiError::bad_request(
            "ref or short_id/content_hash is required",
            Some("ref"),
        ));
    };
    let Some(content_hash) = req.content_hash.as_deref() else {
        return Err(ApiError::bad_request(
            "ref or short_id/content_hash is required",
            Some("content_hash"),
        ));
    };
    parse_short_ref_parts(short_id, content_hash)
}

pub(crate) fn parse_short_ref(reference: &str) -> Result<(String, u8), ApiError> {
    let Some((short_id, content_hash)) = reference.split_once(':') else {
        return Err(ApiError::bad_request(
            "ref must be in shortId:contentHashHex form",
            Some("ref"),
        ));
    };
    parse_short_ref_parts(short_id, content_hash)
}

pub(crate) fn parse_short_ref_parts(
    short_id: &str,
    content_hash: &str,
) -> Result<(String, u8), ApiError> {
    let short_id_bytes = short_id.as_bytes();
    if short_id_bytes.len() < 3
        || !short_id_bytes[0].is_ascii_lowercase()
        || !short_id_bytes[1].is_ascii_lowercase()
        || !short_id_bytes[2..].iter().all(|byte| byte.is_ascii_digit())
    {
        return Err(ApiError::bad_request(
            "short_id must be two lowercase letters followed by decimal digits",
            Some("short_id"),
        ));
    }
    if content_hash.len() != 2 || !content_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request(
            "content_hash must be exactly two hex digits",
            Some("content_hash"),
        ));
    }
    let content_hash = u8::from_str_radix(content_hash, 16)
        .map_err(|_| ApiError::bad_request("content_hash must be hex", Some("content_hash")))?;
    Ok((short_id.to_owned(), content_hash))
}

pub(crate) fn core_list_limit(limit: usize) -> usize {
    limit.min(CORE_MAX_LIST_LIMIT)
}

pub(crate) fn core_list_entities_by_type(
    vault: &oneiron::Vault,
    entity_type: u8,
    params: CoreListQuery,
) -> Result<Json<SearchResponse>, EnvelopedApiError> {
    let view = params.view.unwrap_or(View::Summary);
    let limit = core_list_limit(params.limit);
    let after = params
        .after
        .as_deref()
        .map(|after| parse_entity_id_param(after, "after"))
        .transpose()?;
    let (ids, next_cursor) = collect_live_entity_page(vault, after, limit, |after, limit| {
        vault
            .entities_by_type_page(entity_type, after, limit)
            .map_err(|error| {
                tracing::error!(error = %error, entity_type, "core list failed");
                core_engine_error("core list failed", error).into()
            })
    })?;
    let items = project_entity_ids(vault, ids, view)?;
    let meta = match params.count_mode {
        CountMode::None => ResponseMeta::none(),
        CountMode::Estimate => ResponseMeta::estimate(items.len() as u64),
        CountMode::Exact => {
            let total = count_live_entities_by_type(vault, entity_type)?;
            ResponseMeta::new(total, CountMode::Exact)
        }
    };
    Ok(Json(PaginatedResponse::new(items, next_cursor, meta)))
}

pub(crate) fn collect_live_entity_page<F>(
    vault: &oneiron::Vault,
    after: Option<oneiron::EntityId>,
    limit: usize,
    mut fetch: F,
) -> Result<(Vec<oneiron::EntityId>, Option<String>), EnvelopedApiError>
where
    F: FnMut(
        Option<&oneiron::EntityId>,
        usize,
    ) -> Result<Vec<oneiron::EntityId>, EnvelopedApiError>,
{
    if limit == 0 {
        return Ok((Vec::new(), None));
    }

    let mut cursor = after;
    let mut ids = Vec::with_capacity(limit);
    let mut next_cursor = None;

    while next_cursor.is_none() {
        let remaining = limit.saturating_sub(ids.len());
        let fetch_limit = if remaining == 0 {
            1
        } else {
            remaining.saturating_add(1)
        };
        let fetched = fetch(cursor.as_ref(), fetch_limit)?;
        if fetched.is_empty() {
            break;
        }

        let fetched_len = fetched.len();
        for id in fetched {
            cursor = Some(id);
            if is_deleted_shell_for_core_list(vault, &id)? {
                continue;
            }
            if ids.len() < limit {
                ids.push(id);
            } else {
                next_cursor = ids.last().map(oneiron::EntityId::to_hex);
                break;
            }
        }

        if fetched_len < fetch_limit {
            break;
        }
    }

    Ok((ids, next_cursor))
}

pub(crate) fn count_live_entities_by_type(
    vault: &oneiron::Vault,
    entity_type: u8,
) -> Result<u64, EnvelopedApiError> {
    let mut after = None;
    let mut total = 0_u64;
    loop {
        let ids = vault
            .entities_by_type_page(entity_type, after.as_ref(), CORE_MAX_LIST_LIMIT)
            .map_err(|error| {
                tracing::error!(error = %error, entity_type, "core list count failed");
                core_engine_error("core list count failed", error)
            })?;
        if ids.is_empty() {
            break;
        }
        for id in &ids {
            if !is_deleted_shell_for_core_list(vault, id)? {
                total = total.saturating_add(1);
            }
        }
        after = ids.last().copied();
        if ids.len() < CORE_MAX_LIST_LIMIT {
            break;
        }
    }
    Ok(total)
}

pub(crate) fn is_deleted_shell_for_core_list(
    vault: &oneiron::Vault,
    id: &oneiron::EntityId,
) -> Result<bool, ApiError> {
    vault.is_deleted_shell(id).map_err(|error| {
        tracing::error!(error = %error, id = %id.to_hex(), "core deleted-shell check failed");
        core_engine_error("core deleted-shell check failed", error)
    })
}

pub(crate) fn project_entity_ids(
    vault: &oneiron::Vault,
    ids: Vec<oneiron::EntityId>,
    view: View,
) -> Result<Vec<Value>, ApiError> {
    let mut items = Vec::with_capacity(ids.len());
    for id in ids {
        if is_deleted_shell_for_core_list(vault, &id)? {
            continue;
        }
        if let Some(item) = projection::project_entity(vault, &id, view).map_err(|error| {
            tracing::error!(error = %error, id = %id.to_hex(), "core projection failed");
            core_engine_error("core projection failed", error)
        })? {
            items.push(item);
        }
    }
    Ok(items)
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
