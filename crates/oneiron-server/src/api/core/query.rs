//! Query/list/capability routes and their paging helpers.

use super::super::SearchResponse;
use super::super::core_engine_error;
use super::super::default_limit;
use super::super::json_payload;
use super::super::parse_entity_id_param;
use super::super::scoped_read_for_core_auth;
use super::super::search_fetch_limit;
use super::super::search_meta;
use super::super::search_response;
use super::write_shape::CORE_MAX_LIST_LIMIT;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
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
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use utoipa::IntoParams;
use utoipa::ToSchema;

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
        (Some(query), Some(vector)) => scoped_read.search(query, vector, limit, None),
        (Some(query), None) => scoped_read.search_text(query, limit, None),
        (None, Some(vector)) => scoped_read.search_vector(vector, limit, None),
        (None, None) => Ok(Vec::new()),
    }
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
