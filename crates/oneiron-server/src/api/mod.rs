//! HTTP query routes for web dashboard access.
//!
//! These routes provide server-side query capabilities for clients
//! that don't have a local LMDB vault (e.g., web dashboard).
//!
//! Auth: shared secret header for Phase 1.

#[cfg(test)]
use crate::config::SyncServerConfig;
use crate::error::ApiError;
use crate::idempotency::IdempotencyLayerState;
use crate::idempotency::idempotency_middleware;
use crate::runtime::RuntimeHealthStatus;
use crate::server::SyncServer;
use crate::skills_pack as skills_pack_artifact;
use axum::Router;
#[cfg(test)]
use axum::body::Bytes;
use axum::extract::State;
#[cfg(test)]
use axum::http::header::CACHE_CONTROL;
#[cfg(test)]
use axum::http::header::CONTENT_SECURITY_POLICY;
#[cfg(test)]
use axum::http::header::ETAG;
#[cfg(test)]
use axum::http::header::IF_NONE_MATCH;
#[cfg(test)]
use axum::http::header::LOCATION;
use axum::middleware;
use axum::response::IntoResponse;
use axum::response::Json;
use axum::routing::get;
use axum::routing::post;
#[cfg(test)]
use oneiron::registry::ENTITY_TYPE_TURN;
use serde::Serialize;
#[cfg(test)]
use serde_json::json;
#[cfg(test)]
use std::collections::BTreeSet;
use std::sync::Arc;
use utoipa::ToSchema;

// Test-only seam: `api/tests` names these bare through `use super::*`, but no
// production path in this module does anymore (the items live in the children
// above). A plain import would warn as unused in non-test builds.
#[cfg(test)]
use crate::auth::CoreAuth;
#[cfg(test)]
use crate::error::ApiErrorDetails;
#[cfg(test)]
use crate::error::ErrorCode;
#[cfg(test)]
use crate::projection::View;
#[cfg(test)]
use crate::protocol::CountMode;
#[cfg(test)]
use crate::protocol::PaginatedResponse;
#[cfg(test)]
use crate::protocol::ResponseMeta;
#[cfg(test)]
use crate::runtime::RuntimeMode;
#[cfg(test)]
use crate::runtime::RuntimeProviderKind;
#[cfg(test)]
use crate::runtime::RuntimeRole;
#[cfg(test)]
use axum::extract::Query;
#[cfg(test)]
use axum::http::HeaderMap;

mod artifacts;
// ONE-1819 [BK-08]: the agent-readable booking surface. Its shared executor is
// the sole consumer of the ONE-1817 guards below and the sole door into the
// merged booking solver and lifecycle.
mod booking;
// ONE-1817: booking anti-abuse route-layer guards. ONE-1819's shared executor
// is their consumer; the cache helpers stay ahead of the slot-list handler
// that will serve from them.
#[allow(dead_code)]
mod booking_anti_abuse;
mod campaign;
mod companion;
mod consumer_usage;
mod context_pack;
mod conversations;
mod core;
mod discover;
mod entity;
mod error_map;
// ONE-1441 [WIRE-P1]: the bounded HTTP projection of the engine memory
// surface, nested at `/v1/core/facade`. Its own file because it is its own
// contract — one route per public verb, engine DTOs verbatim, and a facade
// error envelope whose `code` is the engine's raw string rather than this
// crate's closed `ErrorCode`.
mod facade;
// ONE-1908 [ORIGIN-01]: the git smart-HTTP serving surface. Protocol only —
// the serve wire, the door window, and the single-writer landing all live in
// `oneiron::origin::smart_http`.
mod git_http;
mod git_lfs;
mod lease;
mod mcp_gateway;
mod memory;
// ONE-207 [RET-207]: the provider-neutral memory reasoning route. It owns the
// depth cost gate, the extractive answer for the model-free tiers, and the
// citation gate over whatever a host composer returns.
pub(crate) mod memory_reason;
mod openapi;
mod openapi_registry;
mod params;
// ONE-1437: in-process local reactive read contract. No HTTP surface by design
// (the ONE-1925 client-framework binding and the ONE-1495 cloud carrier are its
// consumers), so the non-test build sees a contract with no caller — the
// `protocol::close_codes` posture.
mod context_board;
#[allow(dead_code)]
mod reactive;
mod run_tree;
mod saved_query;
mod scoped_auth;
mod search;
mod surface_events;
mod vad;

pub(crate) use self::artifacts::*;
pub(crate) use self::booking::*;
pub(crate) use self::companion::*;
pub(crate) use self::consumer_usage::*;
pub(crate) use self::context_board::*;
pub(crate) use self::context_pack::*;
pub(crate) use self::conversations::*;
pub(crate) use self::core::*;
pub(crate) use self::discover::*;
pub(crate) use self::entity::*;
use self::error_map::{core_engine_error, json_rejection_error, query_rejection_error};
pub(crate) use self::lease::*;
pub(crate) use self::mcp_gateway::*;
pub(crate) use self::memory::*;
pub(crate) use self::memory_reason::*;
pub(crate) use self::openapi::*;
pub(crate) use self::openapi_registry::ApiDoc;
pub(crate) use self::params::ViewQuery;
use self::params::{
    default_limit, has_json_content_type, hex_bytes, json_payload, parse_entity_id_param,
    parse_optional_entity_id, query_params, unix_seconds_now,
};
pub(crate) use self::reactive::*;
pub(crate) use self::run_tree::*;
use self::scoped_auth::{check_api_auth, scoped_read_for_core_auth, scoped_read_for_legacy_api};
pub(crate) use self::search::*;
pub(crate) use self::surface_events::*;
pub(crate) use self::vad::*;

const API_LEVEL: &str = "v1";
/// Capability-token prefix under which discovery advertises each MCP tool and,
/// for tools with a closed `op` discriminator, each of its operations. The
/// tokens are derived from `crate::mcp::McpToolName`, so the catalog and the
/// advertisement cannot drift.
pub(crate) const MCP_TOOL_CAPABILITY_PREFIX: &str = "mcp.tool.";
// ONE-214 is read-only and adds no notification-specific storage. Keep
// context-board hydration bounded by returning pending notifications from a
// latest window.

/// Builds the HTTP API routes.
pub(crate) fn api_routes(server: Arc<SyncServer>) -> Router {
    let idempotency = IdempotencyLayerState::new(server.clone());
    let legacy_mutation_routes = Router::new()
        // owner recovery surface (ONE-1140, OD-8): revoke a lost/stolen
        // device's lease binding (terminal)
        .route("/api/lease/revoke", post(lease_revoke))
        .route_layer(middleware::from_fn_with_state(
            idempotency.clone(),
            idempotency_middleware,
        ));
    let core_mutation_routes = Router::new()
        .route("/batch", post(core_batch))
        .route("/memory/verbs/{verb}", post(core_memory_verb))
        .route("/conversations", post(create_core_conversation))
        .route(
            "/conversations/{conversation_id}/turns",
            post(create_core_conversation_turn),
        )
        .route("/turns/annotate", post(annotate_turn_vad))
        .route("/surface-events", post(submit_core_surface_event))
        .route_layer(middleware::from_fn_with_state(
            idempotency.clone(),
            idempotency_middleware,
        ));
    let core_routes = Router::new()
        .route("/query", post(core_query))
        .route("/context-pack", post(core_context_pack))
        .route("/context-board", post(context_board_hydrate))
        .route("/hydrate", post(core_hydrate))
        .route("/batch/shortId/hydrate", post(core_batch_short_id_hydrate))
        .route("/run-tree", get(core_run_tree))
        .route("/run-tree/observe", get(core_run_tree_observe))
        .route("/run-tree/intervene", post(core_run_tree_intervene))
        .route("/memory/{id}/timeline", get(core_memory_timeline))
        .route(
            "/outbound/capabilities",
            get(list_core_outbound_capabilities),
        )
        .route(
            "/outbound/capabilities/{connector}",
            get(get_core_outbound_capability),
        )
        .route(
            "/outbound/capabilities/{connector}/verbs/{verb}",
            get(get_core_outbound_verb_contract),
        )
        .route("/conversations", get(list_core_conversations))
        .route(
            "/conversations/{conversation_id}/turns",
            get(list_core_conversation_turns),
        )
        .route("/turns/{turn_id}", get(get_core_turn))
        .route("/turns/annotate", get(read_turn_vad_annotation))
        .route(
            "/surface-events/{correlation_id}",
            get(get_core_surface_event),
        )
        .merge(core_mutation_routes);
    // First-party code-run `self.*` dispatch is host-side only. External
    // clients keep the plain REST verb/batch surface and bring their own runner.
    let companion_mutation_routes = Router::new()
        .route("/access-grants", post(create_companion_access_grant))
        .route("/register/records", post(create_companion_register_record))
        .route(
            "/register/records/{record_id}",
            post(update_companion_register_record),
        )
        .route(
            "/register/records/{record_id}/retire",
            post(retire_companion_register_record),
        )
        .route(
            "/register/records/{record_id}/end-relationship",
            post(end_companion_register_relationship),
        )
        .route(
            "/access-grants/{grant_id}/revoke",
            post(revoke_companion_access_grant),
        )
        .route_layer(middleware::from_fn_with_state(
            idempotency,
            idempotency_middleware,
        ));
    let companion_routes = Router::new()
        .route(
            "/profiles/{persona_ref}",
            get(get_companion_profile).post(refresh_companion_profile),
        )
        .route(
            "/register/records/{record_id}",
            get(get_companion_register_record),
        )
        // ONE-207: the depth-dialed reasoning read. A POST that WRITES
        // NOTHING, so it stays off `companion_mutation_routes` and out of the
        // idempotency layer above: an idempotency key on a pure read would
        // cache an answer against a vault that moves under it, and there is no
        // replayed mutation for the layer to protect.
        .route("/memory/reason", post(companion_memory_reason))
        .merge(companion_mutation_routes);

    Router::new()
        .route("/api/openapi.json", get(openapi_json))
        .route("/api/skills/oneiron.skills.md", get(skills_pack))
        .route("/api/health", get(health))
        .route("/a/{artifact}", get(serve_artifact_root))
        .route("/a/{artifact}/", get(serve_artifact_root))
        .route("/a/{artifact}/{*path}", get(serve_artifact_path))
        // ONE-1704: two SEPARATELY REGISTERED MCP endpoints, each pinned to one
        // immutable surface mode by its route entry. Nothing on the wire moves a
        // connection between them.
        //
        // Each endpoint's registered surface is its WHOLE callable surface: no
        // retired `oneiron.*` plain-verb name resolves on either route.
        //
        // ONE-1704 B1/B8 — the HOST-FREE release contract, and it is FINAL for
        // this prerelease rather than a wiring step someone still has to take.
        // These routes bind no `execute_code` host, this crate ships no
        // production `JsCodeModeRuntime`, LLM backend, or budget lease, and
        // nothing here constructs one. `execute_code` is therefore registered
        // on NEITHER endpoint, is advertised nowhere, and a direct call is
        // refused at the shared name-resolution chokepoint with the stable
        // `execute_code_unavailable` code before any run is created. No example
        // binding is illustrated here, because illustrating one would describe
        // a production seam this release does not have. A production host, its
        // runtime/provider wiring, and the engine settlement door belong to the
        // named follow-on feature ticket, not to these route entries.
        .route("/mcp", post(mcp_gateway))
        .route("/mcp/tool-first", post(mcp_tool_first_gateway))
        .route("/api/core/discover", get(discover))
        .route("/api/search/vector", get(search_vector))
        .route("/api/search/text", get(search_text))
        .route("/api/entity/{id}", get(get_entity))
        .route("/api/edges/{id}", get(get_edges))
        // CA-07's `self.*` surface, at the resource paths ARCH-0059 ratified.
        // Both routers dispatch into `oneiron::campaign::surface`; neither owns
        // campaign semantics.
        .merge(self::campaign::campaign_routes())
        .merge(self::saved_query::saved_query_routes())
        // BK-08's machine-readable booking surface. Every route addresses the
        // page by opaque token and dispatches into the one shared executor.
        .merge(self::booking::booking_routes())
        // ONE-1908: git smart-HTTP. Stock clients clone, fetch, and push here;
        // every route streams through one `git http-backend` child.
        .merge(self::git_http::git_http_routes())
        .nest("/v1/core", core_routes)
        // ONE-1441: the facade projection is its own nest, not an arm inside
        // `core_routes`. Nesting expands each row into a concrete
        // `/v1/core/facade/<verb>` path, so it neither shadows nor is shadowed
        // by the storage-shaped `/v1/core` routes above, and its 64 MiB body
        // limit stays a property of this nest alone.
        .nest("/v1/core/facade", self::facade::facade_routes())
        .nest("/v1/companion", companion_routes)
        .route("/v1/consumer/usage", get(get_consumer_usage))
        .route(
            "/v1/consumer/usage/details",
            get(get_consumer_usage_details),
        )
        .route("/v1/consumer/top-up", post(top_up_consumer))
        .route("/v1/usage/events", post(record_usage_event))
        .route(
            "/v1/usage/tenants/{tenant_id}/rollup",
            get(get_usage_rollup),
        )
        .merge(legacy_mutation_routes)
        .with_state(server)
}

/// Health check endpoint.
#[utoipa::path(
    get,
    path = "/api/health",
    responses(
        (
            status = 200,
            description = "Server is reachable and returns supported capabilities, formats, and rate-limit settings.",
            body = HealthResponse,
            content_type = "application/json",
            example = json!({
                "status": "ok",
                "service": "oneiron-server",
                "capabilities": {
                    "capabilities": ["core.discover", "skills_pack.fetch", "search.vector", "search.text"],
                    "modes": ["flash", "thinking", "pro", "ultra"]
                },
                "formats": ["json", "yaml", "toon", "markdown", "plaintext"],
                "rate_limit": {
                    "api_enforced": false,
                    "websocket_enforced": true,
                    "max_messages_per_sec": 64,
                    "max_windows_per_connection": 8,
                    "max_frame_size_bytes": 1048576,
                    "max_update_payload_bytes": 1048576,
                    "max_ephemeral_payload_bytes": 65536,
                    "max_ephemeral_snapshot_bytes": 262144
                },
                "runtime": {
                    "mode": "local_free",
                    "oneironSpendMetered": false,
                    "state": "available"
                }
            })
        )
    )
)]
async fn health(State(server): State<Arc<SyncServer>>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        service: "oneiron-server",
        capabilities: feature_flags(),
        formats: supported_formats(),
        rate_limit: rate_limit_status(&server.config),
        runtime: runtime_health_status_for_config(&server.config),
    })
}

// ─── Discovery / capability metadata ─────────────────────────────────────────

/// Health response returned by `/api/health`.
#[derive(Serialize, ToSchema)]
struct HealthResponse {
    /// Health status for the HTTP service.
    #[schema(value_type = String, example = "ok")]
    status: &'static str,
    /// Service identifier for this daemon.
    #[schema(value_type = String, example = "oneiron-server")]
    service: &'static str,
    /// Currently advertised API capabilities and execution modes.
    capabilities: FeatureFlags,
    /// Payload formats this API can produce or consume.
    #[schema(value_type = Vec<String>, example = json!(["json", "yaml", "toon", "markdown", "plaintext"]))]
    formats: Vec<&'static str>,
    /// Server-side rate-limit configuration visible to API clients.
    rate_limit: RateLimitStatus,
    /// Redacted aggregate runtime availability for unauthenticated health.
    runtime: RuntimeHealthStatus,
}

// ─── Companion v1 profile access ─────────────────────────────────────────────

// ─── Usage Ledger ────────────────────────────────────────────────────────────

fn require_entity_type(
    server: &SyncServer,
    id: &oneiron::EntityId,
    expected_type: u8,
    resource: &'static str,
) -> Result<(), ApiError> {
    match server.vault.get_entity_type(id) {
        Ok(Some(actual)) if actual == expected_type => Ok(()),
        Ok(Some(_)) => Err(ApiError::bad_request(
            format!("{resource} id does not reference a {resource} entity"),
            Some(resource),
        )),
        Ok(None) => Err(ApiError::not_found(resource, Some(&id.to_hex()))),
        Err(error) => {
            tracing::error!(error = %error, "entity type lookup failed");
            Err(ApiError::internal_server_error("entity type lookup failed"))
        }
    }
}

// ─── Lease revocation (ONE-1140, OD-8) ────────────────────────────────────────

// ─── Context Pack ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
