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
pub(crate) fn check_auth(
    headers: &HeaderMap,
    config_secret: &Option<String>,
) -> Result<(), StatusCode> {
    use subtle::ConstantTimeEq;

    let Some(expected) = config_secret.as_ref() else {
        // No secret configured — allow all (dev mode)
        return Ok(());
    };

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
}

fn default_limit() -> usize {
    10
}

#[derive(Serialize)]
struct SearchResult {
    id: String,
    score: f32,
}

/// Vector similarity search.
/// GET /api/search/vector?query=0.1,0.2,...&limit=10
async fn search_vector(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Query(params): Query<VectorSearchQuery>,
) -> Result<Json<Vec<SearchResult>>, StatusCode> {
    check_auth(&headers, &server.config.auth_secret)?;

    let query: Result<Vec<f32>, _> = params
        .query
        .split(',')
        .map(|s| s.trim().parse::<f32>())
        .collect();

    let query = query.map_err(|_| StatusCode::BAD_REQUEST)?;

    let results = server
        .vault
        .search_vector(&query, params.limit)
        .map_err(|e| {
            tracing::error!(error = %e, "vector search failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let response: Vec<SearchResult> = results
        .into_iter()
        .map(|r| SearchResult {
            id: r.id.to_hex(),
            score: r.score,
        })
        .collect();

    Ok(Json(response))
}

#[derive(Deserialize)]
struct TextSearchQuery {
    query: String,
    #[serde(default = "default_limit")]
    limit: usize,
}

/// BM25 text search.
/// GET /api/search/text?query=hello+world&limit=10
async fn search_text(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Query(params): Query<TextSearchQuery>,
) -> Result<Json<Vec<SearchResult>>, StatusCode> {
    check_auth(&headers, &server.config.auth_secret)?;

    let results = server
        .vault
        .search_text(&params.query, params.limit)
        .map_err(|e| {
            tracing::error!(error = %e, "text search failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let response: Vec<SearchResult> = results
        .into_iter()
        .map(|r| SearchResult {
            id: r.id.to_hex(),
            score: r.score,
        })
        .collect();

    Ok(Json(response))
}

// ─── Entity Routes ────────────────────────────────────────────────────────────

/// Get entity by ID.
/// GET /api/entity/:id
async fn get_entity(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Path(id_hex): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &server.config.auth_secret)?;

    let id = oneiron::EntityId::from_hex(&id_hex).map_err(|_| StatusCode::BAD_REQUEST)?;

    let blob = server.vault.get(&id).map_err(|e| {
        tracing::error!(error = %e, "get entity failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

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
    check_auth(&headers, &server.config.auth_secret)?;

    let id = oneiron::EntityId::from_hex(&id_hex).map_err(|_| StatusCode::BAD_REQUEST)?;

    let edges = server.vault.edges_out(&id).map_err(|e| {
        tracing::error!(error = %e, "get edges failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

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
    check_auth(&headers, &server.config.auth_secret)?;

    // Build context pack using the vault's query API.
    // This is a thin wrapper — full implementation depends on
    // what query parameters the ContextPackBuilder supports.
    // For Phase 1, return a placeholder acknowledging the request.

    Ok(Json(serde_json::json!({
        "status": "ok",
        "message": "context-pack endpoint ready — full implementation pending ContextPackBuilder integration"
    })))
}
