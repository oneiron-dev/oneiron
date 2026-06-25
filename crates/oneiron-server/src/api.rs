//! HTTP query routes for web dashboard access.
//!
//! These routes provide server-side query capabilities for clients
//! that don't have a local LMDB vault (e.g., web dashboard).
//!
//! Auth: shared secret header for Phase 1.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::SyncServerConfig;
use crate::error::ApiError;
use crate::projection::{self, View};
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

fn check_api_auth(headers: &HeaderMap, config: &SyncServerConfig) -> Result<(), ApiError> {
    check_auth(headers, config).map_err(|_| ApiError::unauthorized())
}

fn query_params<T>(query: Result<Query<T>, QueryRejection>) -> Result<T, ApiError> {
    let Query(params) = query.map_err(query_rejection_error)?;
    Ok(params)
}

fn query_rejection_error(rejection: QueryRejection) -> ApiError {
    if rejection.body_text().contains("invalid_view") {
        ApiError::bad_request("view must be one of summary, standard, full", Some("view"))
    } else {
        ApiError::bad_request("invalid query parameters", None)
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
    view: Option<View>,
}

fn default_limit() -> usize {
    10
}

/// Vector similarity search.
/// GET /api/search/vector?query=0.1,0.2,...&limit=10
async fn search_vector(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<VectorSearchQuery>, QueryRejection>,
) -> Result<Json<Vec<Value>>, ApiError> {
    check_api_auth(&headers, &server.config)?;
    let params = query_params(query)?;
    let view = params.view.unwrap_or(View::Summary);

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
        .search_vector(&query, params.limit)
        .inspect_err(|e| {
            tracing::error!(error = %e, "vector search failed");
        })
        .map_err(|_| ApiError::internal_server_error("vector search failed"))?;

    let response = search_response(&server.vault, results, view)?;

    Ok(Json(response))
}

#[derive(Deserialize)]
struct TextSearchQuery {
    query: String,
    #[serde(default = "default_limit")]
    limit: usize,
    view: Option<View>,
}

/// BM25 text search.
/// GET /api/search/text?query=hello+world&limit=10
async fn search_text(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<TextSearchQuery>, QueryRejection>,
) -> Result<Json<Vec<Value>>, ApiError> {
    check_api_auth(&headers, &server.config)?;
    let params = query_params(query)?;
    let view = params.view.unwrap_or(View::Summary);

    let results = server
        .vault
        .search_text(&params.query, params.limit)
        .inspect_err(|e| {
            tracing::error!(error = %e, "text search failed");
        })
        .map_err(|_| ApiError::internal_server_error("text search failed"))?;

    let response = search_response(&server.vault, results, view)?;

    Ok(Json(response))
}

fn search_response(
    vault: &oneiron::Vault,
    results: Vec<oneiron::ScoredEntity>,
    view: View,
) -> Result<Vec<Value>, ApiError> {
    let mut response = Vec::with_capacity(results.len());
    for result in results {
        match projection::project_search_result(vault, result, view) {
            Ok(Some(value)) => response.push(value),
            Ok(None) => continue,
            Err(e) => {
                tracing::error!(error = %e, "search projection failed");
                return Err(ApiError::internal_server_error("search projection failed"));
            }
        }
    }
    Ok(response)
}

// ─── Entity Routes ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ViewQuery {
    view: Option<View>,
}

/// Get entity by ID.
/// GET /api/entity/:id
async fn get_entity(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Path(id_hex): Path<String>,
    query: Result<Query<ViewQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    check_api_auth(&headers, &server.config)?;
    let params = query_params(query)?;
    let view = params.view.unwrap_or(View::Standard);

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

    let Some(data) = blob else {
        return Err(ApiError::not_found("entity", Some(&id_hex)));
    };

    if view == View::Standard {
        return Ok((StatusCode::OK, data).into_response());
    }

    let entity_type = server
        .vault
        .get_entity_type(&id)
        .inspect_err(|e| {
            tracing::error!(error = %e, "get entity type failed");
        })
        .map_err(|_| ApiError::internal_server_error("get entity type failed"))?
        .ok_or_else(|| ApiError::not_found("entity", Some(&id_hex)))?;
    let updated_at = server
        .vault
        .get_learned_at(&id)
        .inspect_err(|e| {
            tracing::error!(error = %e, "get entity learned_at failed");
        })
        .map_err(|_| ApiError::internal_server_error("get entity learned_at failed"))?;
    let response = projection::project_entity_parts(&id, entity_type, updated_at, &data, view);

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Get outbound edges for an entity.
/// GET /api/edges/:id
async fn get_edges(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Path(id_hex): Path<String>,
    query: Result<Query<ViewQuery>, QueryRejection>,
) -> Result<Json<Vec<Value>>, ApiError> {
    check_api_auth(&headers, &server.config)?;
    let params = query_params(query)?;
    let view = params.view.unwrap_or(View::Summary);

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

    let response: Vec<Value> = edges
        .into_iter()
        .map(|edge| projection::project_edge(&edge, view))
        .collect();

    Ok(Json(response))
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
    fn search_response_drops_stale_hydrated_hits() {
        let dir = tempfile::tempdir().unwrap();
        let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap();
        let stale_hit = oneiron::ScoredEntity {
            id: oneiron::EntityId::now(),
            score: 0.75,
        };

        for view in [View::Summary, View::Full] {
            let response = search_response(&vault, vec![stale_hit], view).unwrap();
            assert!(
                response.is_empty(),
                "{view:?} should skip missing search hits"
            );
        }
    }
}
