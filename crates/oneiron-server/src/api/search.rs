use super::check_api_auth;
use super::default_limit;
use super::memory_reason::{
    DeepAdmission, admit_deep_retrieval, depth_search_error, minimal_effort,
};
use super::query_params;
use super::scoped_read_for_legacy_api;
use crate::embedder::EmbedQueryRefusal;
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
use oneiron::Effort;
use oneiron::claim::ScopedRead;
use oneiron::retrieval_depth::{DepthSearchRequest, DepthSearchResult, SearchProbe};
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
    /// Retrieval effort: `minimal`, `standard`, or `deep`. Omitted means
    /// `minimal` — one direct vector channel, exactly what this endpoint did
    /// before the dial existed.
    #[serde(default = "minimal_effort")]
    #[schema(value_type = String, default = "minimal", example = "standard")]
    #[param(value_type = String, default = "minimal", example = "standard")]
    pub(crate) depth: Effort,
    /// The text this embedding was produced from. Optional at `minimal` and
    /// `standard`, which never read it, and REQUIRED at `deep`, whose
    /// decomposition and cross-encoder scoring operate on language.
    #[serde(default, rename = "queryText")]
    #[schema(example = "project kickoff notes")]
    #[param(example = "project kickoff notes")]
    pub(crate) query_text: Option<String>,
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
        ),
        (
            status = 503,
            description = "Deep retrieval is unavailable without an admitted budget and host backend.",
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
    check_api_auth(&headers, &server)?;
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

    // The one refusal this endpoint owns rather than delegates: an embedding
    // carries no question, so a deep read over it would have to invent the
    // text it decomposes. Field-specific, and raised before the vault is
    // touched.
    if params.depth == Effort::Deep && probe_text(params.query_text.as_deref()).is_none() {
        return Err(ApiError::bad_request(
            "queryText is required when depth=deep on vector search",
            Some("queryText"),
        ));
    }
    let admission = admit_deep_retrieval(&server, params.depth)?;

    let scoped_read = scoped_read_for_legacy_api(&server.vault)?;
    let results = run_depth_search(
        &scoped_read,
        SearchProbe::Vector {
            embedding: query,
            query_text: probe_text(params.query_text.as_deref()).map(str::to_owned),
        },
        params.depth,
        fetch_limit,
        admission.as_ref(),
    )?;

    let total = results.hits.len();
    let meta = search_meta(count_mode, total).with_quality(&results.retrieval_quality);
    let response = search_response(&scoped_read, results.hits, view, params.limit)?;

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
    /// Retrieval effort: `minimal`, `standard`, or `deep`. Omitted means
    /// `minimal` — one direct BM25 channel, exactly what this endpoint did
    /// before the dial existed.
    #[serde(default = "minimal_effort")]
    #[schema(value_type = String, default = "minimal", example = "standard")]
    #[param(value_type = String, default = "minimal", example = "standard")]
    pub(crate) depth: Effort,
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
        ),
        (
            status = 503,
            description = "Deep retrieval is unavailable without an admitted budget and host backend.",
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
    check_api_auth(&headers, &server)?;
    let params = query_params(query)?;
    let view = params.view.unwrap_or(View::Summary);

    let count_mode = params.count_mode.for_search_response();
    let fetch_limit = search_fetch_limit(count_mode, params.limit);
    let admission = admit_deep_retrieval(&server, params.depth)?;
    let scoped_read = scoped_read_for_legacy_api(&server.vault)?;
    let results = run_depth_search(
        &scoped_read,
        SearchProbe::Text {
            query: params.query,
        },
        params.depth,
        fetch_limit,
        admission.as_ref(),
    )?;

    let total = results.hits.len();
    let meta = search_meta(count_mode, total).with_quality(&results.retrieval_quality);
    let response = search_response(&scoped_read, results.hits, view, params.limit)?;

    Ok(Json(PaginatedResponse::new(response, None, meta)))
}

/// A blank `queryText` is an ABSENT one.
///
/// `?queryText=` on a URL is what an unset form field serializes to, and
/// treating that empty string as "the caller supplied text" would let a deep
/// vector read past the grounding check with nothing to decompose.
fn probe_text(query_text: Option<&str>) -> Option<&str> {
    query_text.map(str::trim).filter(|text| !text.is_empty())
}

/// The one place both raw search endpoints enter the effort dial.
///
/// Shared so the two cannot drift into different tier semantics for the same
/// `depth` value, and so a hit's own accounting stays where it belongs: these
/// endpoints return a paginated hit list with no place to report backend
/// spend, so a deep read here settles its lease against what it actually
/// spent and reports nothing further.
fn run_depth_search(
    scoped_read: &ScopedRead<'_>,
    probe: SearchProbe,
    effort: Effort,
    limit: usize,
    admission: Option<&DeepAdmission>,
) -> Result<DepthSearchResult, ApiError> {
    // A zero-limit page was an empty 200 on this endpoint before the dial
    // existed, and the dial is not the place to turn it into a refusal.
    if limit == 0 {
        return Ok(DepthSearchResult::default());
    }
    let request = DepthSearchRequest {
        probe,
        effort,
        limit,
        session_scope: None,
        lease: admission.map(DeepAdmission::lease),
        backend: admission.map(DeepAdmission::search_backend),
        token_budget: None,
    };
    let result = scoped_read.search_with_effort(&request);
    if let Some(admission) = admission {
        admission.record_usage(result.as_ref().map_or_else(
            |failure| failure.tokens_used,
            |retrieved| retrieved.tokens_used,
        ));
    }
    let result = result.map_err(|failure| depth_search_error(failure.error));
    match admission {
        Some(admission) => admission.finish(result),
        None => result,
    }
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

/// Maximum request text for a semantic read. A query is a question, not a
/// corpus; anything larger is a document that belongs on the write path.
const MAX_SEMANTIC_TEXT_BYTES: usize = 8 * 1024;

/// Request body for semantic search.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(example = json!({
    "text": "what did we decide about the embedder slot",
    "limit": 10,
    "countMode": "estimate"
}))]
pub(crate) struct SemanticSearchRequest {
    /// Natural-language query. The server embeds it with the active provider,
    /// prefixed by the model's query instruction.
    #[schema(example = "what did we decide about the embedder slot")]
    pub(crate) text: String,
    /// Maximum number of nearest entities to return. Defaults to `10`.
    #[serde(default = "default_limit")]
    #[schema(default = default_limit, example = 10)]
    pub(crate) limit: usize,
    /// Optional projection view for returned items. Defaults to `summary`.
    #[schema(example = "summary")]
    pub(crate) view: Option<View>,
    /// Count precision for response metadata. Search defaults to estimate.
    #[serde(default = "CountMode::default_estimate", rename = "countMode")]
    #[schema(example = "estimate")]
    pub(crate) count_mode: CountMode,
    /// Retrieval effort: `minimal`, `standard`, or `deep`. Omitted means
    /// `minimal`.
    #[serde(default = "minimal_effort")]
    #[schema(value_type = String, default = "minimal", example = "standard")]
    pub(crate) depth: Effort,
}

/// Semantic search: the server embeds the query text itself.
///
/// The same vector channel `GET /api/search/vector` reads, reached without the
/// caller owning a copy of the model. The embedding space is the vault's, so a
/// caller cannot accidentally probe one space with another's vector — which is
/// the whole reason this door exists beside the raw one rather than replacing
/// it.
#[utoipa::path(
    post,
    path = "/api/search/semantic",
    request_body = SemanticSearchRequest,
    responses(
        (
            status = 200,
            description = "Semantic search results ordered by the vault retrieval engine, plus the embedder that produced the probe.",
            body = Object,
            content_type = "application/json",
            example = json!({
                "items": [{
                    "id": "0123456789abcdef0123456789abcdef",
                    "kind": "claim",
                    "label": "the embedder slot is a selection",
                    "updatedAt": 1782357635_u64
                }],
                "meta": {
                    "total": 1,
                    "countMode": "estimate"
                },
                "embedder": {
                    "provider": "local",
                    "modelId": "microsoft/harrier-oss-v1-0.6b@f9b9dc8d367d443f2479d27aa5d8d2850c0774ee",
                    "dimensions": 1024
                }
            })
        ),
        (
            status = 400,
            description = "Empty query text or invalid body.",
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
            status = 413,
            description = "Query text exceeds the 8 KB cap.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Vector search or projection failed.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 503,
            description = "No embedder is serving, or deep retrieval is unavailable.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
pub(crate) async fn search_semantic(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    body: Result<Json<SemanticSearchRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    check_api_auth(&headers, &server)?;
    let Json(params) = body.map_err(|rejection| {
        ApiError::bad_request(format!("invalid semantic search body: {rejection}"), None)
    })?;
    let text = params.text.trim();
    if text.is_empty() {
        return Err(ApiError::bad_request(
            "text must not be empty",
            Some("text"),
        ));
    }
    if params.text.len() > MAX_SEMANTIC_TEXT_BYTES {
        return Err(ApiError::payload_too_large(
            "text",
            MAX_SEMANTIC_TEXT_BYTES,
            params.text.len(),
        ));
    }
    let descriptor = server
        .embedder_descriptor()
        .ok_or_else(ApiError::embedder_unavailable)?;
    let embedding = server
        .embed_query_off_runtime(text.to_owned())
        .await
        .map_err(embed_query_error)?;

    let view = params.view.unwrap_or(View::Summary);
    let count_mode = params.count_mode.for_search_response();
    let fetch_limit = search_fetch_limit(count_mode, params.limit);
    let admission = admit_deep_retrieval(&server, params.depth)?;
    let scoped_read = scoped_read_for_legacy_api(&server.vault)?;
    let results = run_depth_search(
        &scoped_read,
        SearchProbe::Vector {
            embedding,
            // Semantic search HAS the question, so a deep read over it needs no
            // second argument from the caller: the text that produced the
            // probe is the text the decomposition reads.
            query_text: Some(text.to_owned()),
        },
        params.depth,
        fetch_limit,
        admission.as_ref(),
    )?;

    let total = results.hits.len();
    let meta = search_meta(count_mode, total).with_quality(&results.retrieval_quality);
    let items = search_response(&scoped_read, results.hits, view, params.limit)?;
    let mut response = serde_json::to_value(PaginatedResponse::new(items, None, meta))
        .map_err(|_| ApiError::internal_server_error("search projection failed"))?;
    if let Value::Object(object) = &mut response {
        object.insert(
            "embedder".to_owned(),
            json!({
                "provider": descriptor.provider,
                "modelId": descriptor.model_id,
                "dimensions": descriptor.dimensions,
            }),
        );
    }
    Ok(Json(response))
}

/// A refusal the caller can act on, with no detail about the deployment.
fn embed_query_error(refusal: EmbedQueryRefusal) -> ApiError {
    match refusal {
        EmbedQueryRefusal::NotConfigured | EmbedQueryRefusal::NotReady => {
            ApiError::embedder_unavailable()
        }
        EmbedQueryRefusal::Failed => ApiError::internal_server_error("query embedding failed"),
    }
}
