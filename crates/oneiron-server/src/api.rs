//! HTTP query routes for web dashboard access.
//!
//! These routes provide server-side query capabilities for clients
//! that don't have a local LMDB vault (e.g., web dashboard).
//!
//! Auth: shared secret header for Phase 1.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};

use crate::config::SyncServerConfig;
use crate::error::ApiError;
use crate::protocol::{CountMode, PaginatedResponse, ResponseMeta};
use crate::server::SyncServer;

const API_LEVEL: &str = "v1";
const SUPPORTED_FORMATS: &[&str] = &["json", "yaml", "toon", "markdown", "plaintext"];
const EFFECTIVE_AUTH_SCOPES: &[&str] = &[
    "core:discover",
    "vault:read",
    "search:read",
    "entity:read",
    "sync:connect",
];
const CAPABILITIES: &[&str] = &[
    "core.discover",
    "health.capabilities",
    "search.vector",
    "search.text",
    "entity.get",
    "edges.get",
    "context_pack",
    "lease.revoke",
];
const CAPABILITY_MODES: &[&str] = &["flash", "thinking", "pro", "ultra"];

/// Builds the HTTP API routes.
pub(crate) fn api_routes(server: Arc<SyncServer>) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/core/discover", get(discover))
        .route("/api/search/vector", get(search_vector))
        .route("/api/search/text", get(search_text))
        .route("/api/entity/{id}", get(get_entity))
        .route("/api/edges/{id}", get(get_edges))
        // context-pack is POST since it takes a complex options body
        .route("/api/context-pack", post(context_pack))
        // owner recovery surface (ONE-1140, OD-8): revoke a lost/stolen
        // device's lease binding (terminal)
        .route("/api/lease/revoke", post(lease_revoke))
        .with_state(server)
}

/// Health check endpoint.
async fn health(State(server): State<Arc<SyncServer>>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        service: "oneiron-server",
        capabilities: feature_flags(),
        formats: supported_formats(),
        rate_limit: rate_limit_status(&server.config),
    })
}

/// Validates the auth secret from request headers.
///
/// Uses constant-time comparison to prevent timing side-channel attacks.
/// Shared by the HTTP API routes and the `/ws` upgrade handler (Phase-1
/// shared-secret scheme).
pub(crate) fn check_auth(headers: &HeaderMap, config: &SyncServerConfig) -> Result<(), StatusCode> {
    use subtle::ConstantTimeEq;

    let Some(expected) = config.auth_secret.as_ref() else {
        return if config.allow_unauthenticated {
            Ok(())
        } else {
            Err(StatusCode::UNAUTHORIZED)
        };
    };
    if expected.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let provided = headers
        .get("x-oneiron-secret")
        .and_then(|v| v.to_str().ok());

    match provided {
        Some(s) if s.len() == expected.len() && s.as_bytes().ct_eq(expected.as_bytes()).into() => {
            Ok(())
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

fn check_api_auth(headers: &HeaderMap, config: &SyncServerConfig) -> Result<(), ApiError> {
    check_auth(headers, config).map_err(|_| ApiError::unauthorized())
}

// ─── Discovery / capability metadata ─────────────────────────────────────────

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    capabilities: FeatureFlags,
    formats: Vec<&'static str>,
    rate_limit: RateLimitStatus,
}

#[derive(Serialize)]
struct DiscoverResponse {
    api_version: &'static str,
    formats: Vec<&'static str>,
    scopes: Vec<&'static str>,
    bound: BoundContext,
    personas: Vec<DiscoveredEntity>,
    conversations: Vec<DiscoveredEntity>,
    feature_flags: FeatureFlags,
    counts: BTreeMap<String, u64>,
    predicate_namespaces: Vec<String>,
    last_activity: Option<u64>,
}

#[derive(Serialize)]
struct BoundContext {
    vault: Option<String>,
    persona: Option<String>,
    conversation: Option<String>,
}

#[derive(Serialize)]
struct DiscoveredEntity {
    id: String,
    entity_type: u8,
}

#[derive(Serialize)]
struct FeatureFlags {
    capabilities: Vec<&'static str>,
    modes: Vec<&'static str>,
}

#[derive(Serialize)]
struct RateLimitStatus {
    api_enforced: bool,
    websocket_enforced: bool,
    max_messages_per_sec: u32,
    max_windows_per_connection: usize,
    max_frame_size_bytes: usize,
    max_update_payload_bytes: usize,
}

/// Vault bootstrap discovery for external agents with only the Phase-1 auth
/// secret. This is read-only aggregation over existing vault indexes and
/// server config; it does not mint identity, mutate auth, or persist state.
/// GET /api/core/discover
async fn discover(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<DiscoverResponse>, ApiError> {
    check_api_auth(&headers, &server.config)?;
    discover_response(&server).map(Json)
}

fn discover_response(server: &SyncServer) -> Result<DiscoverResponse, ApiError> {
    let mut counts = BTreeMap::new();
    let mut personas = Vec::new();
    let mut conversations = Vec::new();
    let mut claim_ids = Vec::new();
    let mut last_activity = None;

    for entity_type in u8::MIN..=u8::MAX {
        let ids = server
            .vault
            .entities_by_type(entity_type)
            .inspect_err(|e| {
                tracing::error!(error = %e, entity_type, "discover count scan failed");
            })
            .map_err(|_| ApiError::internal_server_error("discover count scan failed"))?;

        if ids.is_empty() {
            continue;
        }

        counts.insert(entity_type.to_string(), ids.len() as u64);

        for id in &ids {
            let learned_at = server
                .vault
                .get_learned_at(id)
                .inspect_err(|e| {
                    tracing::error!(error = %e, id = %id.to_hex(), "discover activity scan failed");
                })
                .map_err(|_| ApiError::internal_server_error("discover activity scan failed"))?;
            last_activity =
                Some(last_activity.map_or(learned_at, |current: u64| current.max(learned_at)));
        }

        match entity_type {
            oneiron::types::ENTITY_TYPE_CLAIM => claim_ids.extend(ids),
            oneiron::types::ENTITY_TYPE_PERSON => {
                personas = discovered_entities(&ids, entity_type);
            }
            oneiron::types::ENTITY_TYPE_CONVERSATION => {
                conversations = discovered_entities(&ids, entity_type);
            }
            _ => {}
        }
    }

    Ok(DiscoverResponse {
        api_version: API_LEVEL,
        formats: supported_formats(),
        scopes: EFFECTIVE_AUTH_SCOPES.to_vec(),
        bound: BoundContext {
            vault: None,
            persona: None,
            conversation: None,
        },
        personas,
        conversations,
        feature_flags: feature_flags(),
        counts,
        predicate_namespaces: predicate_namespaces(&server.vault, &claim_ids)?,
        last_activity,
    })
}

fn discovered_entities(ids: &[oneiron::EntityId], entity_type: u8) -> Vec<DiscoveredEntity> {
    ids.iter()
        .map(|id| DiscoveredEntity {
            id: id.to_hex(),
            entity_type,
        })
        .collect()
}

fn predicate_namespaces(
    vault: &oneiron::Vault,
    claim_ids: &[oneiron::EntityId],
) -> Result<Vec<String>, ApiError> {
    let mut namespaces = BTreeSet::new();
    for id in claim_ids {
        let Some(claim) = vault
            .get_claim(id)
            .inspect_err(|e| {
                tracing::error!(error = %e, id = %id.to_hex(), "discover predicate scan failed");
            })
            .map_err(|_| ApiError::internal_server_error("discover predicate scan failed"))?
        else {
            continue;
        };
        if let Some(namespace) = claim.predicate.split('.').next() {
            namespaces.insert(namespace.to_owned());
        }
    }
    Ok(namespaces.into_iter().collect())
}

fn supported_formats() -> Vec<&'static str> {
    SUPPORTED_FORMATS.to_vec()
}

fn feature_flags() -> FeatureFlags {
    FeatureFlags {
        capabilities: CAPABILITIES.to_vec(),
        modes: CAPABILITY_MODES.to_vec(),
    }
}

fn rate_limit_status(config: &SyncServerConfig) -> RateLimitStatus {
    RateLimitStatus {
        api_enforced: false,
        websocket_enforced: config.max_messages_per_sec > 0
            && config.max_windows_per_connection > 0,
        max_messages_per_sec: config.max_messages_per_sec,
        max_windows_per_connection: config.max_windows_per_connection,
        max_frame_size_bytes: config.max_frame_size,
        max_update_payload_bytes: config.max_update_payload,
    }
}

// ─── Search Routes ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct VectorSearchQuery {
    /// Comma-separated f32 values for the query vector.
    query: String,
    /// Maximum results to return.
    #[serde(default = "default_limit")]
    limit: usize,
    /// Count precision for response metadata. Search defaults to estimate.
    #[serde(default = "CountMode::default_estimate", rename = "countMode")]
    count_mode: CountMode,
}

fn default_limit() -> usize {
    10
}

#[derive(Serialize)]
struct SearchResult {
    id: String,
    score: f32,
}

type SearchResponse = PaginatedResponse<SearchResult>;

/// Vector similarity search.
/// GET /api/search/vector?query=0.1,0.2,...&limit=10&countMode=estimate
async fn search_vector(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Query(params): Query<VectorSearchQuery>,
) -> Result<Json<SearchResponse>, ApiError> {
    check_api_auth(&headers, &server.config)?;

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

    let results = server
        .vault
        .search_vector(&query, fetch_limit)
        .inspect_err(|e| {
            tracing::error!(error = %e, "vector search failed");
        })
        .map_err(|_| ApiError::internal_server_error("vector search failed"))?;

    let total = results.len();
    let response: Vec<SearchResult> = results
        .into_iter()
        .take(params.limit)
        .map(|r| SearchResult {
            id: r.id.to_hex(),
            score: r.score,
        })
        .collect();
    let meta = search_meta(count_mode, total);

    Ok(Json(PaginatedResponse::new(response, None, meta)))
}

#[derive(Deserialize)]
struct TextSearchQuery {
    query: String,
    #[serde(default = "default_limit")]
    limit: usize,
    /// Count precision for response metadata. Search defaults to estimate.
    #[serde(default = "CountMode::default_estimate", rename = "countMode")]
    count_mode: CountMode,
}

/// BM25 text search.
/// GET /api/search/text?query=hello+world&limit=10&countMode=estimate
async fn search_text(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Query(params): Query<TextSearchQuery>,
) -> Result<Json<SearchResponse>, ApiError> {
    check_api_auth(&headers, &server.config)?;

    let count_mode = params.count_mode.for_search_response();
    let fetch_limit = search_fetch_limit(count_mode, params.limit);
    let results = server
        .vault
        .search_text(&params.query, fetch_limit)
        .inspect_err(|e| {
            tracing::error!(error = %e, "text search failed");
        })
        .map_err(|_| ApiError::internal_server_error("text search failed"))?;

    let total = results.len();
    let response: Vec<SearchResult> = results
        .into_iter()
        .take(params.limit)
        .map(|r| SearchResult {
            id: r.id.to_hex(),
            score: r.score,
        })
        .collect();
    let meta = search_meta(count_mode, total);

    Ok(Json(PaginatedResponse::new(response, None, meta)))
}

fn search_fetch_limit(count_mode: CountMode, page_limit: usize) -> usize {
    match count_mode {
        CountMode::None => page_limit,
        CountMode::Estimate => page_limit.saturating_add(1),
        CountMode::Exact => unreachable!("search responses never report exact counts"),
    }
}

fn search_meta(count_mode: CountMode, estimated_total: usize) -> ResponseMeta {
    match count_mode {
        CountMode::None => ResponseMeta::none(),
        CountMode::Estimate => ResponseMeta::estimate(estimated_total as u64),
        CountMode::Exact => unreachable!("search responses never report exact counts"),
    }
}

// ─── Entity Routes ────────────────────────────────────────────────────────────

/// Get entity by ID.
/// GET /api/entity/:id
async fn get_entity(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Path(id_hex): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    check_api_auth(&headers, &server.config)?;

    let id = oneiron::EntityId::from_hex(&id_hex).map_err(|_| {
        ApiError::bad_request("entity id must be a 32-character hex entity id", Some("id"))
    })?;

    let blob = server
        .vault
        .get(&id)
        .inspect_err(|e| {
            tracing::error!(error = %e, "get entity failed");
        })
        .map_err(|_| ApiError::internal_server_error("get entity failed"))?;

    match blob {
        Some(data) => Ok((StatusCode::OK, data)),
        None => Err(ApiError::not_found("entity", Some(&id_hex))),
    }
}

/// Get outbound edges for an entity.
/// GET /api/edges/:id
async fn get_edges(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Path(id_hex): Path<String>,
) -> Result<Json<Vec<EdgeResult>>, ApiError> {
    check_api_auth(&headers, &server.config)?;

    let id = oneiron::EntityId::from_hex(&id_hex).map_err(|_| {
        ApiError::bad_request("entity id must be a 32-character hex entity id", Some("id"))
    })?;

    let edges = server
        .vault
        .edges_out(&id)
        .inspect_err(|e| {
            tracing::error!(error = %e, "get edges failed");
        })
        .map_err(|_| ApiError::internal_server_error("get edges failed"))?;

    let response: Vec<EdgeResult> = edges
        .into_iter()
        .map(|e| EdgeResult {
            kind: e.kind as u8,
            target: e.target.to_hex(),
            weight: e.weight,
            created_at: e.created_at,
        })
        .collect();

    Ok(Json(response))
}

#[derive(Serialize)]
struct EdgeResult {
    kind: u8,
    target: String,
    weight: f32,
    created_at: u64,
}

// ─── Lease revocation (ONE-1140, OD-8) ────────────────────────────────────────

#[derive(Deserialize)]
struct LeaseRevokeRequest {
    /// The binding's registry key: 16 lowercase hex chars (`{:016x}`).
    client_id: String,
}

#[derive(Serialize)]
struct LeaseRevokeResponse {
    revoked: bool,
}

/// Revokes a device-lease binding (owner recovery, OD-8 — terminal for the
/// binding; auth = Phase-1 shared secret, same as every API route). The
/// registry change is broadcast to all live connections so replica `ls:`
/// mirrors converge without a reconnect.
/// POST /api/lease/revoke  body: {"client_id": "<16 hex>"}
async fn lease_revoke(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Json(req): Json<LeaseRevokeRequest>,
) -> Result<Json<LeaseRevokeResponse>, ApiError> {
    check_api_auth(&headers, &server.config)?;

    if req.client_id.len() != 16
        || !req
            .client_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ApiError::bad_request(
            "client_id must be exactly 16 lowercase hex characters",
            Some("client_id"),
        ));
    }
    let client_id = u64::from_str_radix(&req.client_id, 16).map_err(|_| {
        ApiError::bad_request(
            "client_id must be exactly 16 lowercase hex characters",
            Some("client_id"),
        )
    })?;

    match server.revoke_lease(client_id).await {
        Ok(Some(update)) => {
            let msg = crate::protocol::encode_root_update(&update);
            let _ = crate::broadcast::broadcast(&server.broadcast_tx, 0, msg);
            Ok(Json(LeaseRevokeResponse { revoked: true }))
        }
        Ok(None) => Ok(Json(LeaseRevokeResponse { revoked: false })),
        Err(e) => {
            tracing::error!(error = %e, "lease revoke failed");
            Err(ApiError::internal_server_error("lease revoke failed"))
        }
    }
}

// ─── Context Pack ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[allow(dead_code)] // Fields deserialized from JSON, used in Phase 1D context-pack endpoint
struct ContextPackRequest {
    /// Query text for retrieval.
    query: Option<String>,
    /// Query vector (as list of f32).
    query_vector: Option<Vec<f32>>,
    /// Maximum entities to retrieve.
    #[serde(default = "default_limit")]
    limit: usize,
}

/// Context pack assembly.
/// POST /api/context-pack
async fn context_pack(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Json(_req): Json<ContextPackRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_api_auth(&headers, &server.config)?;

    // Build context pack using the vault's query API.
    // This is a thin wrapper — full implementation depends on
    // what query parameters the ContextPackBuilder supports.
    // For Phase 1, return a placeholder acknowledging the request.

    Ok(Json(serde_json::json!({
        "status": "ok",
        "message": "context-pack endpoint ready — full implementation pending ContextPackBuilder integration"
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_queries_default_to_estimate_count_mode() {
        let text: TextSearchQuery = serde_json::from_value(serde_json::json!({
            "query": "hello"
        }))
        .unwrap();
        assert_eq!(text.limit, default_limit());
        assert_eq!(text.count_mode, CountMode::Estimate);

        let vector: VectorSearchQuery = serde_json::from_value(serde_json::json!({
            "query": "0.0,0.0"
        }))
        .unwrap();
        assert_eq!(vector.limit, default_limit());
        assert_eq!(vector.count_mode, CountMode::Estimate);
    }

    #[test]
    fn search_meta_honors_none_without_counting() {
        assert_eq!(search_meta(CountMode::None, 25), ResponseMeta::none());
        assert_eq!(search_fetch_limit(CountMode::None, 25), 25);
    }

    #[test]
    fn search_meta_reports_estimate_not_exact() {
        assert_eq!(
            search_meta(CountMode::Estimate, 7),
            ResponseMeta::estimate(7)
        );
        assert_eq!(search_fetch_limit(CountMode::Estimate, 7), 8);
        assert_eq!(CountMode::Exact.for_search_response(), CountMode::Estimate);
    }
}
