//! HTTP query routes for web dashboard access.
//!
//! These routes provide server-side query capabilities for clients
//! that don't have a local LMDB vault (e.g., web dashboard).
//!
//! Auth: shared secret header for Phase 1.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};

use crate::config::SyncServerConfig;
use crate::protocol::{CountMode, PaginatedResponse, ResponseMeta};
use crate::server::SyncServer;

/// Builds the HTTP API routes.
pub(crate) fn api_routes(server: Arc<SyncServer>) -> Router {
    Router::new()
        .route("/api/health", get(health))
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
async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "oneiron-server"
    }))
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
) -> Result<Json<SearchResponse>, StatusCode> {
    check_auth(&headers, &server.config)?;

    let count_mode = params.count_mode;
    let query: Result<Vec<f32>, _> = params
        .query
        .split(',')
        .map(|s| s.trim().parse::<f32>())
        .collect();

    let query = query.map_err(|_| StatusCode::BAD_REQUEST)?;

    let results = server
        .vault
        .search_vector(&query, params.limit)
        .inspect_err(|e| {
            tracing::error!(error = %e, "vector search failed");
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let response: Vec<SearchResult> = results
        .into_iter()
        .map(|r| SearchResult {
            id: r.id.to_hex(),
            score: r.score,
        })
        .collect();
    let meta = search_meta(count_mode, response.len());

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
) -> Result<Json<SearchResponse>, StatusCode> {
    check_auth(&headers, &server.config)?;

    let count_mode = params.count_mode;
    let results = server
        .vault
        .search_text(&params.query, params.limit)
        .inspect_err(|e| {
            tracing::error!(error = %e, "text search failed");
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let response: Vec<SearchResult> = results
        .into_iter()
        .map(|r| SearchResult {
            id: r.id.to_hex(),
            score: r.score,
        })
        .collect();
    let meta = search_meta(count_mode, response.len());

    Ok(Json(PaginatedResponse::new(response, None, meta)))
}

fn search_meta(requested: CountMode, visible_items: usize) -> ResponseMeta {
    match requested.for_search_response() {
        CountMode::None => ResponseMeta::none(),
        CountMode::Estimate => ResponseMeta::estimate(visible_items as u64),
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
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &server.config)?;

    let id = oneiron::EntityId::from_hex(&id_hex).map_err(|_| StatusCode::BAD_REQUEST)?;

    let blob = server
        .vault
        .get(&id)
        .inspect_err(|e| {
            tracing::error!(error = %e, "get entity failed");
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match blob {
        Some(data) => Ok((StatusCode::OK, data)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Get outbound edges for an entity.
/// GET /api/edges/:id
async fn get_edges(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Path(id_hex): Path<String>,
) -> Result<Json<Vec<EdgeResult>>, StatusCode> {
    check_auth(&headers, &server.config)?;

    let id = oneiron::EntityId::from_hex(&id_hex).map_err(|_| StatusCode::BAD_REQUEST)?;

    let edges = server
        .vault
        .edges_out(&id)
        .inspect_err(|e| {
            tracing::error!(error = %e, "get edges failed");
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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
) -> Result<Json<LeaseRevokeResponse>, StatusCode> {
    check_auth(&headers, &server.config)?;

    if req.client_id.len() != 16
        || !req
            .client_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let client_id = u64::from_str_radix(&req.client_id, 16).map_err(|_| StatusCode::BAD_REQUEST)?;

    match server.revoke_lease(client_id).await {
        Ok(Some(update)) => {
            let msg = crate::protocol::encode_root_update(&update);
            let _ = crate::broadcast::broadcast(&server.broadcast_tx, 0, msg);
            Ok(Json(LeaseRevokeResponse { revoked: true }))
        }
        Ok(None) => Ok(Json(LeaseRevokeResponse { revoked: false })),
        Err(e) => {
            tracing::error!(error = %e, "lease revoke failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
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
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_auth(&headers, &server.config)?;

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
    }

    #[test]
    fn search_meta_reports_estimate_not_exact() {
        assert_eq!(
            search_meta(CountMode::Estimate, 7),
            ResponseMeta::estimate(7)
        );
        assert_eq!(search_meta(CountMode::Exact, 7), ResponseMeta::estimate(7));
    }
}
