use super::check_api_auth;
use super::context_pack::embed_semantic_text;
use super::core_engine_error;
use super::default_limit;
use super::memory_reason::{
    DeepAdmission, admit_deep_retrieval, depth_search_error, minimal_effort,
};
use super::query_params;
use super::scoped_read_for_legacy_api;
use crate::auth::Locality;
use crate::embedder::EmbedQueryRefusal;
use crate::error::ApiError;
use crate::projection;
use crate::projection::View;
use crate::protocol::CountMode;
use crate::protocol::PaginatedResponse;
use crate::protocol::ResponseMeta;
use crate::server::{QueryDoor, SyncServer, query_caller};
use axum::extract::Query;
use axum::extract::State;
use axum::extract::rejection::QueryRejection;
use axum::http::HeaderMap;
use axum::response::Json;
use oneiron::Effort;
use oneiron::claim::ScopedRead;
use oneiron::embed::InputKind;
use oneiron::retrieval_depth::{
    DepthSearchRequest, DepthSearchResult, RetrievalDeadline, SearchProbe,
};
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;
use utoipa::IntoParams;
use utoipa::ToSchema;

mod deadline;
use deadline::{
    SearchPage, read_by_deadline, search_deadline, search_page, search_page_by_deadline,
};

/// Search responses always preserve each executed read receipt.
#[derive(Serialize)]
pub(crate) struct ScopedSearchResponse {
    #[serde(flatten)]
    response: super::SearchResponse,
    narrowing: Vec<oneiron::claim::ScopedReadReceipt>,
    /// On a machine that syncs only what it opened, the home's answer to a
    /// text search (OF-534).
    #[serde(skip_serializing_if = "Option::is_none")]
    residence: Option<ResidenceAnswer>,
}
impl ScopedSearchResponse {
    /// Says whether the request's `limit` was served at the ceiling; a page
    /// its deadline cut says it too.
    fn limit_clamped(mut self, clamped: bool) -> Self {
        self.response.meta.limit_clamped = clamped;
        self
    }

    fn residence(mut self, answer: Option<ResidenceAnswer>) -> Self {
        self.residence = answer;
        self
    }
}
impl std::ops::Deref for ScopedSearchResponse {
    type Target = super::SearchResponse;
    fn deref(&self) -> &Self::Target {
        &self.response
    }
}

/// The home's answer to a text search on a machine that syncs only what it
/// opened (OF-534). `home` is complete; `localOnly` is not: the home was out
/// of reach or not asked, and the hits are this device's opened items alone.
/// A hit the page lacks is one the device does not hold; its window opens it.
#[derive(Serialize)]
struct ResidenceAnswer {
    source: &'static str,
    complete: bool,
    hits: Vec<ResidenceAnswerHit>,
}

#[derive(Serialize)]
struct ResidenceAnswerHit {
    id: String,
    score: f32,
    window: String,
}

impl ResidenceAnswer {
    /// The local page alone, which the home did not complete.
    fn local_only() -> Self {
        Self {
            source: "localOnly",
            complete: false,
            hits: Vec::new(),
        }
    }
}

impl From<oneiron::sync::ResidenceSearch> for ResidenceAnswer {
    fn from(search: oneiron::sync::ResidenceSearch) -> Self {
        Self {
            source: match search.source {
                oneiron::sync::SearchSource::Home => "home",
                oneiron::sync::SearchSource::LocalOnly => "localOnly",
            },
            complete: search.complete,
            hits: search
                .hits
                .into_iter()
                .map(|hit| ResidenceAnswerHit {
                    id: hit.entity_id,
                    score: hit.score,
                    window: hit.window.to_string(),
                })
                .collect(),
        }
    }
}

/// Asks the home a text search an opened machine cannot answer locally
/// (ARCH-0023b partial sync). `None` on a machine that holds every window.
/// The home scopes its answer to this device's own grants, so only an
/// owner-grade caller gets its hits; a narrower one gets the local page,
/// marked incomplete. A deadline bounds the ask as it bounds the page.
async fn ask_home(
    home: Option<Arc<oneiron::sync::HomeSearch>>,
    owner_grade: bool,
    query: String,
    limit: usize,
    due: Option<Instant>,
) -> Option<ResidenceAnswer> {
    let home = home?;
    if !owner_grade {
        return Some(ResidenceAnswer::local_only());
    }
    let search = home.search(&query, limit);
    let answer = match due {
        Some(due) => tokio::time::timeout_at(due.into(), search).await.ok(),
        None => Some(search.await),
    };
    // A refused or late ask leaves the local page, marked incomplete.
    Some(match answer {
        Some(Ok(search)) => search.into(),
        Some(Err(_)) | None => ResidenceAnswer::local_only(),
    })
}

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
    #[schema(value_type = String, default = "light", example = "medium")]
    #[param(value_type = String, default = "light", example = "medium")]
    pub(crate) depth: Effort,
    /// The text this embedding was produced from. Optional at `minimal` and
    /// `standard`, which never read it, and REQUIRED at `deep`, whose
    /// decomposition and cross-encoder scoring operate on language.
    #[serde(default, rename = "queryText")]
    #[schema(example = "project kickoff notes")]
    #[param(example = "project kickoff notes")]
    pub(crate) query_text: Option<String>,
    /// A hard deadline in milliseconds, 1 to 60000: the search answers with
    /// the hits ready when it comes due, and `meta.partial` says so.
    /// Omitted, the search runs to the end.
    #[serde(default, rename = "deadlineMs")]
    #[schema(example = 100)]
    #[param(example = 100)]
    pub(crate) deadline_ms: Option<u64>,
    /// A declared embedding space to search in place of the vault's own text
    /// index (OF-370), as `GET /v1/owner/embedding-spaces` lists it. The
    /// vector must come from one of the space's query towers, at its width.
    #[serde(default)]
    #[schema(example = "local/clip-vit-b32@2024-01@own-server")]
    #[param(example = "local/clip-vit-b32@2024-01@own-server")]
    pub(crate) space: Option<String>,
    /// The query tower that encoded `query` when `space` is set: `text`
    /// (the default), `image` or `audio`.
    #[serde(default, rename = "queryKind")]
    #[schema(value_type = Option<String>, example = "image")]
    #[param(value_type = Option<String>, example = "image")]
    pub(crate) query_kind: Option<InputKind>,
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
            description = "Malformed query vector or invalid query parameters, an undeclared `space`, or a vector the space's `queryKind` tower does not take at the space's width.",
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
            description = "`queryText` exceeds `[limits].retrieval_query_bytes` (1 MiB unless set); the error names the field, the bound and the bytes received.",
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
    Locality(locality): Locality,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<VectorSearchQuery>, QueryRejection>,
) -> Result<Json<ScopedSearchResponse>, ApiError> {
    let arrived = Instant::now();
    let auth = check_api_auth(&headers, &server)?.at(locality);
    let params = query_params(query)?;
    if let Some(text) = params.query_text.as_deref() {
        server.check_retrieval_query(
            query_caller(&auth),
            QueryDoor::SearchVector,
            "queryText",
            text,
        )?;
    }
    let (page_limit, clamped) = oneiron::memory::caps::clamp_search_limit(params.limit);
    let deadline = search_deadline(params.deadline_ms)?;
    let view = params.view.unwrap_or(View::Summary);

    let count_mode = params.count_mode.for_search_response();
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
    if params.depth.requires_rerank() && probe_text(params.query_text.as_deref()).is_none() {
        return Err(ApiError::bad_request(
            "queryText is required when depth=deep on vector search",
            Some("queryText"),
        ));
    }
    let query_text = probe_text(params.query_text.as_deref()).map(str::to_owned);
    let probe = match params.space {
        Some(space) => {
            let query_kind = params.query_kind.unwrap_or(InputKind::Text);
            let declared = server
                .vault
                .embedding_spaces()
                .map_err(|error| core_engine_error("embedding spaces read failed", error))?
                .into_iter()
                .find(|declared| declared.id == space)
                .ok_or_else(|| {
                    ApiError::bad_request(
                        format!("embedding space {space} is not declared"),
                        Some("space"),
                    )
                })?;
            declared
                .admit_query(query_kind, &query)
                .map_err(|error| ApiError::bad_request(error.to_string(), Some("query")))?;
            SearchProbe::Space {
                space,
                query_kind,
                embedding: query,
                query_text,
            }
        }
        None if params.query_kind.is_some() => {
            return Err(ApiError::bad_request(
                "queryKind names a tower of a declared space; set space too",
                Some("queryKind"),
            ));
        }
        None => SearchProbe::Vector {
            embedding: query,
            query_text,
        },
    };
    let page = SearchPage {
        probe,
        depth: params.depth,
        view,
        count_mode,
        page_limit,
        auth,
    };
    search_page_by_deadline(server, arrived, deadline, page)
        .await
        .map(|page| Json(page.limit_clamped(clamped)))
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
    #[schema(value_type = String, default = "light", example = "medium")]
    #[param(value_type = String, default = "light", example = "medium")]
    pub(crate) depth: Effort,
    /// A hard deadline in milliseconds, 1 to 60000: the search answers with
    /// the hits ready when it comes due, and `meta.partial` says so.
    /// Omitted, the search runs to the end.
    #[serde(default, rename = "deadlineMs")]
    #[schema(example = 100)]
    #[param(example = 100)]
    pub(crate) deadline_ms: Option<u64>,
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
            status = 413,
            description = "`query` exceeds `[limits].retrieval_query_bytes` (1 MiB unless set); the error names the field, the bound and the bytes received.",
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
    Locality(locality): Locality,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<TextSearchQuery>, QueryRejection>,
) -> Result<Json<ScopedSearchResponse>, ApiError> {
    let arrived = Instant::now();
    let auth = check_api_auth(&headers, &server)?.at(locality);
    let params = query_params(query)?;
    server.check_retrieval_query(
        query_caller(&auth),
        QueryDoor::SearchText,
        "query",
        &params.query,
    )?;
    let (page_limit, clamped) = oneiron::memory::caps::clamp_search_limit(params.limit);
    let deadline = search_deadline(params.deadline_ms)?;
    // An opened machine asks its home alongside its own page (OF-534).
    let home = ask_home(
        server.vault().home_search(),
        auth.is_owner_grade(),
        params.query.clone(),
        page_limit,
        deadline.map(|budget| arrived + budget),
    );
    let page = SearchPage {
        probe: SearchProbe::Text {
            query: params.query,
        },
        depth: params.depth,
        view: params.view.unwrap_or(View::Summary),
        count_mode: params.count_mode.for_search_response(),
        page_limit,
        auth,
    };
    let (page, residence) = tokio::join!(
        search_page_by_deadline(server, arrived, deadline, page),
        home
    );
    page.map(|page| Json(page.limit_clamped(clamped).residence(residence)))
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
    deadline: Option<&RetrievalDeadline>,
) -> Result<DepthSearchResult, ApiError> {
    // A zero-limit page was an empty 200 on this endpoint before the dial
    // existed, and the dial is not the place to turn it into a refusal.
    if limit == 0 {
        return Ok(DepthSearchResult {
            narrowing: vec![
                scoped_read
                    .read_receipt(None, 0)
                    .map_err(|_| ApiError::internal_server_error("read receipt failed"))?,
            ],
            ..Default::default()
        });
    }
    let request = DepthSearchRequest {
        deadline,
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

#[cfg(test)]
pub(crate) fn search_response(
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    results: Vec<oneiron::ScoredEntity>,
    view: View,
    page_limit: usize,
) -> Result<oneiron::claim::ScopedReadResult<Vec<Value>>, ApiError> {
    let mut bodies = projection::BodyBudget::new(
        scoped_read.vault(),
        crate::config::LimitsConfig::default().projection_body_bytes,
    );
    search_response_with_revisions(
        scoped_read,
        results,
        None,
        view,
        page_limit,
        None,
        None,
        &mut bodies,
    )
}

fn search_depth_response(
    scoped_read: &ScopedRead<'_>,
    results: &DepthSearchResult,
    view: View,
    page_limit: usize,
    bodies: &mut projection::BodyBudget<'_>,
) -> Result<oneiron::claim::ScopedReadResult<Vec<Value>>, ApiError> {
    // finish_scoped appends the final intersection of the channel receipts.
    let requested = results
        .narrowing
        .last()
        .map(|receipt| receipt.applied.as_filter());
    search_response_with_revisions(
        scoped_read,
        results.hits.clone(),
        Some(&results.revisions),
        view,
        page_limit,
        None,
        requested.as_ref(),
        bodies,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one axis of the one page projection"
)]
pub(crate) fn search_response_with_revisions(
    scoped_read: &ScopedRead<'_>,
    results: Vec<oneiron::ScoredEntity>,
    revisions: Option<&std::collections::HashMap<oneiron::EntityId, oneiron::memory::RevisionRef>>,
    view: View,
    page_limit: usize,
    observations: Option<&mut oneiron::context_board::SessionReadSet>,
    requested: Option<&oneiron::RetrievalFilter>,
    bodies: &mut projection::BodyBudget<'_>,
) -> Result<oneiron::claim::ScopedReadResult<Vec<Value>>, ApiError> {
    let selected: Vec<_> = results
        .into_iter()
        .filter_map(|result| {
            let mode = match revisions {
                Some(revisions) => oneiron::memory::ReadMode::Pinned(*revisions.get(&result.id)?),
                None => oneiron::memory::ReadMode::Indexed,
            };
            Some((result, mode))
        })
        .collect();
    let refs: Vec<_> = selected
        .iter()
        .map(|(row, mode)| oneiron::claim::PointRead::id(row.id).at(*mode))
        .collect();
    let read = scoped_read.read(&refs, requested).map_err(|error| {
        tracing::error!(kind = ?error.kind(), "search projection failed");
        ApiError::internal_server_error("search projection failed")
    })?;
    let mut receipt = read.receipt;
    let mut staged = observations.as_deref().cloned();
    let mut response = Vec::with_capacity(selected.len().min(page_limit));
    for ((result, mode), row) in selected.into_iter().zip(read.value) {
        let Some(oneiron::claim::ReadRow {
            entity_type,
            learned_at,
            body: Some(body),
            ..
        }) = row
        else {
            continue;
        };
        // All overfetch rows were validated in the page snapshot. Observe only served rows.
        if response.len() >= page_limit {
            continue;
        }
        // A body is decoded, to project it or to observe it, only while the
        // page's body budget holds it; Standard alone projects none.
        let decoded =
            (matches!(view, View::Standard) && staged.is_none()) || bodies.admits(body.len());
        if decoded
            && let Some(observations) = staged.as_mut()
            && let Some(successor) = observations
                .observe_snapshot(
                    scoped_read,
                    result.id,
                    entity_type,
                    &body,
                    matches!(view, View::Full),
                )
                .map_err(|error| {
                    tracing::error!(kind = ?error.kind(), "search observation failed");
                    ApiError::internal_server_error("search projection failed")
                })?
        {
            receipt.restrict_with(&successor);
        }
        let mut value = if matches!(view, View::Standard) {
            json!({"id": result.id.to_hex(), "score": result.score})
        } else if decoded {
            projection::project_entity_parts(&result.id, entity_type, learned_at, &body, view)
        } else {
            bodies.omitted(&result.id, entity_type, learned_at, &body, view, mode)
        };
        if matches!(view, View::Full)
            && let Value::Object(object) = &mut value
        {
            object.insert("score".to_owned(), json!(result.score));
        }
        response.push(value);
    }
    if let (Some(target), Some(staged)) = (observations, staged) {
        *target = staged;
    }
    Ok(oneiron::claim::ScopedReadResult {
        value: response,
        receipt,
    })
}

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
    /// prefixed by the model's query instruction; on the one-space preset,
    /// through the text tower of the space the text kind slot binds.
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
    #[schema(value_type = String, default = "light", example = "medium")]
    pub(crate) depth: Effort,
    /// A hard deadline in milliseconds from arrival, 1 to 60000, the query's
    /// embedding included: the search answers with the hits ready when it
    /// comes due, and `meta.partial` says so. Omitted, it runs to the end.
    #[serde(default)]
    #[schema(example = 100)]
    pub(crate) deadline_ms: Option<u64>,
}

/// Semantic search: the server embeds the query text itself.
///
/// The same vector channel `GET /api/search/vector` reads, reached without the
/// caller owning a copy of the model. The embedding space is the vault's, so a
/// caller cannot accidentally probe one space with another's vector — which is
/// the whole reason this door exists beside the raw one rather than replacing
/// it. On the one-space preset (the text kind slot bound to a declared space,
/// OF-370) the query embeds through that space's `ai.embed` rung and searches
/// that space, and `embedder` names the space.
#[utoipa::path(
    post,
    path = "/api/search/semantic",
    request_body = SemanticSearchRequest,
    responses(
        (
            status = 200,
            description = "Semantic search results ordered by the vault retrieval engine, plus the embedder that produced the probe: the active provider, or `{\"space\": id}` when the text kind slot binds a declared space (the one-space preset).",
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
                    "modelId": "perplexity-ai/pplx-embed-v1-0.6b@2c4d510dd4a732063c31a0f70193e35067b51fd8",
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
            description = "Query text exceeds `[limits].retrieval_query_bytes` (1 MiB unless set); the error names the field, the bound and the bytes received.",
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
            description = "No embedder is serving (on the one-space preset, no `ai.embed` rung serves the text slot's space), or deep retrieval is unavailable.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
pub(crate) async fn search_semantic(
    headers: HeaderMap,
    Locality(locality): Locality,
    State(server): State<Arc<SyncServer>>,
    body: Result<Json<SemanticSearchRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let arrived = Instant::now();
    let auth = check_api_auth(&headers, &server)?.at(locality);
    let Json(params) = body.map_err(|rejection| {
        ApiError::bad_request(format!("invalid semantic search body: {rejection}"), None)
    })?;
    server.check_retrieval_query(
        query_caller(&auth),
        QueryDoor::SearchSemantic,
        "text",
        &params.text,
    )?;
    let deadline = search_deadline(params.deadline_ms)?;
    let text = params.text.trim();
    if text.is_empty() {
        return Err(ApiError::bad_request(
            "text must not be empty",
            Some("text"),
        ));
    }
    // On the one-space preset the text kind slot binds a declared space: the
    // query embeds through that space's text tower and searches it, and the
    // vault's own text index, which no text search reads then, is not asked.
    let space = server
        .vault
        .kind_slot_bindings()
        .map_err(|error| core_engine_error("kind slot bindings read failed", error))?
        .text;
    let embedder = match &space {
        Some(space) => json!({ "space": space }),
        None => {
            let descriptor = server
                .embedder_descriptor()
                .ok_or_else(ApiError::embedder_unavailable)?;
            json!({
                "provider": descriptor.provider,
                "modelId": descriptor.model_id,
                "dimensions": descriptor.dimensions,
            })
        }
    };
    let count_mode = params.count_mode.for_search_response();
    let (page_limit, clamped) = oneiron::memory::caps::clamp_search_limit(params.limit);
    let (depth, view) = (params.depth, params.view.unwrap_or(View::Summary));
    let page_auth = auth.clone();
    let page_space = space.clone();
    // Semantic search HAS the question, so a deep read over it needs no
    // second argument from the caller: the text that produced the probe is
    // the text the decomposition reads.
    let page = move |embedding, question| SearchPage {
        probe: match page_space.clone() {
            Some(space) => SearchProbe::Space {
                space,
                query_kind: InputKind::Text,
                embedding,
                query_text: Some(question),
            },
            None => SearchProbe::Vector {
                embedding,
                query_text: Some(question),
            },
        },
        depth,
        view,
        count_mode,
        page_limit,
        auth: page_auth.clone(),
    };
    let question = text.to_owned();
    let page = match deadline {
        None => {
            let embedding = match &space {
                Some(space) => embed_semantic_text(&server, space.clone(), &question).await?,
                None => server
                    .embed_query_off_runtime(question.clone())
                    .await
                    .map_err(embed_query_error)?,
            };
            let admission = admit_deep_retrieval(&server, depth)?;
            search_page(&server, page(embedding, question), admission.as_ref(), None)?
        }
        // Under a deadline the embedding spends the same budget: it runs
        // inside the read, so one still running when the deadline comes due
        // leaves the page empty and partial. The request is admitted first.
        Some(budget) => {
            let admission = admit_deep_retrieval(&server, depth)?;
            let runtime = tokio::runtime::Handle::current();
            read_by_deadline(
                Arc::clone(&server),
                arrived,
                budget,
                count_mode,
                auth,
                move |server, deadline| {
                    let embedding = match space {
                        Some(space) => {
                            runtime.block_on(embed_semantic_text(server, space, &question))?
                        }
                        None => server.embed_query(&question).map_err(embed_query_error)?,
                    };
                    search_page(
                        server,
                        page(embedding, question),
                        admission.as_ref(),
                        Some(deadline),
                    )
                },
            )
            .await?
        }
    };
    let mut response = serde_json::to_value(page.limit_clamped(clamped))
        .map_err(|_| ApiError::internal_server_error("search projection failed"))?;
    if let Value::Object(object) = &mut response {
        object.insert("embedder".to_owned(), embedder);
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
