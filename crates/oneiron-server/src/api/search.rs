use super::check_api_auth;
use super::default_limit;
use super::query_params;
use super::scoped_read_for_legacy_api;
use crate::error::ApiError;
use crate::projection;
use crate::projection::View;
use crate::protocol::CountMode;
use crate::protocol::PaginatedResponse;
use crate::protocol::ResponseMeta;
use crate::server::SyncServer;
use axum::extract::Query;
use axum::extract::State;
use axum::extract::rejection::QueryRejection;
use axum::http::HeaderMap;
use axum::response::Json;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;
use utoipa::IntoParams;
use utoipa::ToSchema;

/// Query parameters for vector similarity search.
#[derive(Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
#[schema(example = json!({
    "query": "0.12,-0.04,0.98",
    "limit": 10,
    "countMode": "estimate"
}))]
pub(crate) struct VectorSearchQuery {
    /// Comma-separated `f32` embedding values used as the vector search probe.
    #[schema(example = "0.12,-0.04,0.98")]
    #[param(example = "0.12,-0.04,0.98")]
    pub(crate) query: String,
    /// Maximum number of nearest entities to return. Defaults to `10` when omitted.
    #[serde(default = "default_limit")]
    #[schema(default = default_limit, example = 10)]
    #[param(default = 10, example = 10)]
    pub(crate) limit: usize,
    /// Optional projection view for returned items. Defaults to `summary`.
    #[schema(example = "summary")]
    #[param(example = "summary")]
    pub(crate) view: Option<View>,
    /// Count precision for response metadata. Search defaults to estimate.
    #[serde(default = "CountMode::default_estimate", rename = "countMode")]
    #[schema(example = "estimate")]
    #[param(example = "estimate")]
    pub(crate) count_mode: CountMode,
}

/// Search hit returned by vector and text search endpoints.
#[derive(Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": "0123456789abcdef0123456789abcdef",
    "score": 0.87
}))]
pub(crate) struct SearchResult {
    /// Hex-encoded entity id for the matched vault record.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: String,
    /// Ranking score from the selected retrieval engine; vector search reports the vector score or distance, while text search reports BM25 relevance. Compare scores only within one response.
    #[schema(example = 0.87)]
    score: f32,
}

pub(crate) type SearchResponse = PaginatedResponse<Value>;

/// Vector similarity search.
#[utoipa::path(
    get,
    path = "/api/search/vector",
    params(VectorSearchQuery),
    responses(
        (
            status = 200,
            description = "Vector search results ordered by the vault retrieval engine. Items are projection objects selected by `view`; `view=standard` returns `SearchResult` objects.",
            body = Object,
            content_type = "application/json",
            example = json!({
                "items": [{
                    "id": "0123456789abcdef0123456789abcdef",
                    "kind": "task",
                    "label": "Project kickoff notes",
                    "updatedAt": 1782357635_u64
                }],
                "meta": {
                    "total": 1,
                    "countMode": "estimate"
                }
            })
        ),
        (
            status = 400,
            description = "Malformed query vector or invalid query parameters.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid bearer credentials.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Vector search or projection failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
pub(crate) async fn search_vector(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<VectorSearchQuery>, QueryRejection>,
) -> Result<Json<SearchResponse>, ApiError> {
    check_api_auth(&headers, &server.config)?;
    let params = query_params(query)?;
    let view = params.view.unwrap_or(View::Summary);

    let count_mode = params.count_mode.for_search_response();
    let fetch_limit = search_fetch_limit(count_mode, params.limit);
    let query: Result<Vec<f32>, _> = params
        .query
        .split(',')
        .map(|s| s.trim().parse::<f32>())
        .collect();

    let query = query.map_err(|_| {
        ApiError::bad_request(
            "query must be a comma-separated list of f32 values",
            Some("query"),
        )
    })?;

    let scoped_read = scoped_read_for_legacy_api(&server.vault)?;
    let results = scoped_read
        .search_vector(&query, fetch_limit)
        .inspect_err(|e| {
            tracing::error!(error = %e, "vector search failed");
        })
        .map_err(|_| ApiError::internal_server_error("vector search failed"))?;

    let total = results.len();
    let response = search_response(&scoped_read, results, view, params.limit)?;
    let meta = search_meta(count_mode, total);

    Ok(Json(PaginatedResponse::new(response, None, meta)))
}

/// Query parameters for BM25 text search.
#[derive(Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
#[schema(example = json!({
    "query": "project kickoff notes",
    "limit": 10,
    "countMode": "estimate"
}))]
pub(crate) struct TextSearchQuery {
    /// Natural-language or keyword query used by the BM25 text index.
    #[schema(example = "project kickoff notes")]
    #[param(example = "project kickoff notes")]
    pub(crate) query: String,
    /// Maximum number of text hits to return. Defaults to `10` when omitted.
    #[serde(default = "default_limit")]
    #[schema(default = default_limit, example = 10)]
    #[param(default = 10, example = 10)]
    pub(crate) limit: usize,
    /// Optional projection view for returned items. Defaults to `summary`.
    #[schema(example = "summary")]
    #[param(example = "summary")]
    pub(crate) view: Option<View>,
    /// Count precision for response metadata. Search defaults to estimate.
    #[serde(default = "CountMode::default_estimate", rename = "countMode")]
    #[schema(example = "estimate")]
    #[param(example = "estimate")]
    pub(crate) count_mode: CountMode,
}

/// BM25 text search.
#[utoipa::path(
    get,
    path = "/api/search/text",
    params(TextSearchQuery),
    responses(
        (
            status = 200,
            description = "BM25 text search results ordered by relevance. Items are projection objects selected by `view`; `view=standard` returns `SearchResult` objects.",
            body = Object,
            content_type = "application/json",
            example = json!({
                "items": [{
                    "id": "fedcba9876543210fedcba9876543210",
                    "kind": "task",
                    "label": "Project kickoff notes",
                    "updatedAt": 1782357635_u64
                }],
                "meta": {
                    "total": 1,
                    "countMode": "estimate"
                }
            })
        ),
        (
            status = 400,
            description = "Invalid query parameters.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid bearer credentials.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Text search or projection failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
pub(crate) async fn search_text(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<TextSearchQuery>, QueryRejection>,
) -> Result<Json<SearchResponse>, ApiError> {
    check_api_auth(&headers, &server.config)?;
    let params = query_params(query)?;
    let view = params.view.unwrap_or(View::Summary);

    let count_mode = params.count_mode.for_search_response();
    let fetch_limit = search_fetch_limit(count_mode, params.limit);
    let scoped_read = scoped_read_for_legacy_api(&server.vault)?;
    let results = scoped_read
        .search_text(&params.query, fetch_limit)
        .inspect_err(|e| {
            tracing::error!(error = %e, "text search failed");
        })
        .map_err(|_| ApiError::internal_server_error("text search failed"))?;

    let total = results.len();
    let response = search_response(&scoped_read, results, view, params.limit)?;
    let meta = search_meta(count_mode, total);

    Ok(Json(PaginatedResponse::new(response, None, meta)))
}

pub(crate) fn search_fetch_limit(count_mode: CountMode, page_limit: usize) -> usize {
    match count_mode {
        CountMode::None => page_limit,
        CountMode::Estimate => page_limit.saturating_add(1),
        CountMode::Exact => unreachable!("search responses never report exact counts"),
    }
}

pub(crate) fn search_meta(count_mode: CountMode, estimated_total: usize) -> ResponseMeta {
    match count_mode {
        CountMode::None => ResponseMeta::none(),
        CountMode::Estimate => ResponseMeta::estimate(estimated_total as u64),
        CountMode::Exact => unreachable!("search responses never report exact counts"),
    }
}

pub(crate) fn search_response(
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    results: Vec<oneiron::ScoredEntity>,
    view: View,
    page_limit: usize,
) -> Result<Vec<Value>, ApiError> {
    let mut response = Vec::with_capacity(results.len().min(page_limit));
    for result in results {
        match project_scoped_search_result(scoped_read, result, view) {
            Ok(Some(value)) if response.len() < page_limit => response.push(value),
            Ok(Some(_)) => continue,
            Ok(None) => continue,
            Err(e) => {
                tracing::error!(error = %e, "search projection failed");
                return Err(ApiError::internal_server_error("search projection failed"));
            }
        }
    }
    Ok(response)
}

pub(crate) fn project_scoped_search_result(
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    result: oneiron::ScoredEntity,
    view: View,
) -> oneiron::Result<Option<Value>> {
    let id_hex = result.id.to_hex();
    match view {
        View::Standard => Ok(Some(json!({
            "id": id_hex,
            "score": result.score,
        }))),
        View::Summary | View::Full => {
            let Some((entity_type, learned_at, body)) = scoped_read.get_entity_parts(&result.id)?
            else {
                return Ok(None);
            };
            let mut value =
                projection::project_entity_parts(&result.id, entity_type, learned_at, &body, view);
            if matches!(view, View::Full)
                && let Value::Object(object) = &mut value
            {
                object.insert("score".to_owned(), json!(result.score));
            }
            Ok(Some(value))
        }
    }
}
