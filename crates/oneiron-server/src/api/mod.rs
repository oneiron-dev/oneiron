//! HTTP query routes for web dashboard access.
//!
//! These routes provide server-side query capabilities for clients
//! that don't have a local LMDB vault (e.g., web dashboard).
//!
//! Auth: logged capability slips, bound to the holder key.

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
use crate::projection::View;
#[cfg(test)]
use crate::runtime::RuntimeMode;
#[cfg(test)]
use crate::runtime::RuntimeProviderKind;
#[cfg(test)]
use crate::runtime::RuntimeRole;
#[cfg(test)]
use axum::http::HeaderMap;

pub(crate) mod ai;
mod anonymous_chat;
mod artifacts;
// OF-469: a kept authority checkpoint and its attestations, for adoption.
mod authority_checkpoint;
// OF-511: the artifact family's contract routes (versions, made_by, born-from,
// export, proposals, Keep/Discard/Undo).
mod blob_artifacts;
// OF-604: zstd and gzip request bodies, and compressed JSON replies.
mod body_codec;
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
mod client_metadata;
mod companion;
mod consumer_usage;
mod context_pack;
mod conversation_dag;
mod conversation_members;
mod conversation_transcript;
mod conversations;
mod cooperative_deletion;
mod core;
mod discover;
mod entity;
mod error_map;
mod esign;
pub(crate) use self::esign::hold_worker::spawn as spawn_esign_hold_worker;
#[cfg(unix)]
pub(crate) use self::esign::seal_worker::spawn as spawn_esign_seal_worker;
mod off_record_rooms;
mod org_admin;
mod pairing;
mod sessions;
// ONE-1441 [WIRE-P1]: the bounded HTTP projection of the engine memory
// surface, nested at `/v1/core/facade`. Its own file because it is its own
// contract — one route per public verb, engine DTOs verbatim, and a facade
// error envelope whose `code` is the engine's raw string rather than this
// crate's closed `ErrorCode`.
mod facade;
// OF-489: the held socket runs every facade verb through the facade's one
// generated dispatch, under the credential its connection bound.
pub(crate) use self::facade::{
    FacadeApiError, FacadeCall, ai_speech_for_run, call_verb as facade_call_verb,
    connector_call_as, self_use_as,
};
mod feedback_inbox;
pub(crate) use self::feedback_inbox::FloodCap;
// ONE-1908 [ORIGIN-01]: the git smart-HTTP serving surface. Protocol only —
// the serve wire, the door window, and the single-writer landing all live in
// `oneiron::origin::smart_http`.
mod git_http;
mod git_lfs;
mod transfer;
pub(crate) use self::transfer::{LFS_MEMORY_ROOM, Transfers};
mod lease;
mod llm;
#[cfg(feature = "mesh")]
pub(crate) use llm::MeshLlm;
mod mcp_gateway;
mod memory;
// ONE-207 [RET-207]: the provider-neutral memory reasoning route. It owns the
// depth cost gate, the extractive answer for the model-free tiers, and the
// citation gate over whatever a host composer returns.
pub(crate) mod memory_reason;
// OF-445: the OpenAI-compatible memory-injection proxy.
mod openai_proxy;
mod openapi;
mod openapi_registry;
// OF-163: the host operator's own acts, behind the host's root credential.
mod operator_routes;
// OF-559/OF-202/OF-211/OF-296: the owner's own actions — backups, the secret
// scan switch, whole-batch import consent and whole-run agent consent.
mod owner_origin;
mod owner_routes;
pub(crate) use owner_routes::owner;
mod packs;
mod params;
// ONE-1437: in-process local reactive read contract. No HTTP surface by design
// (the ONE-1925 client-framework binding and the ONE-1495 cloud carrier are its
// consumers), so the non-test build sees a contract with no caller — the
// `protocol::close_codes` posture.
pub(crate) mod call_receipt;
mod context_board;
#[allow(dead_code)]
mod reactive;
mod report;
mod run_tree;
mod saved_query;
mod scoped_auth;
mod search;
mod surface_events;
mod vad;
pub(crate) mod write_facet;

pub(crate) use self::artifacts::*;
pub(crate) use self::booking::*;
pub(crate) use self::companion::*;
pub(crate) use self::consumer_usage::*;
pub(crate) use self::context_board::*;
pub(crate) use self::context_pack::*;
pub(crate) use self::conversation_dag::*;
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
use self::scoped_auth::{check_api_auth, scoped_read_for_legacy_api};
pub(crate) use self::scoped_auth::{
    credential_memory, credential_read_key, scoped_read_for_core_auth,
};
pub(crate) use self::search::*;
pub(crate) use self::surface_events::*;
pub(crate) use self::vad::*;

const API_LEVEL: &str = "v1";
/// Capability-token prefix under which discovery advertises each MCP tool. The
/// tokens are derived from the registered surfaces' tool names, so `tools/list`
/// and the advertisement cannot drift.
pub(crate) const MCP_TOOL_CAPABILITY_PREFIX: &str = "mcp.tool.";
// ONE-214 is read-only and adds no notification-specific storage. Keep
// context-board hydration bounded by returning pending notifications from a
// latest window.

/// Builds the HTTP API routes.
pub(crate) fn api_routes(server: Arc<SyncServer>) -> Router {
    crate::wire_telemetry::start_window_receipts(&server);
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
        .route("/org-admin/{org}/policy", post(org_admin::configure))
        .route("/batch", post(core_batch))
        .route("/propose", post(core_propose))
        .route("/memory/verbs/{verb}", post(core_memory_verb))
        .route("/conversations", post(create_core_conversation))
        .route(
            "/conversations/{conversation_id}/members",
            post(conversation_members::write_member),
        )
        .route(
            "/conversations/{conversation_id}/records",
            post(append_core_record),
        )
        .route(
            "/conversations/{conversation_id}/records/{record}/thread",
            post(reply_in_thread),
        )
        .route("/messages/{message}/reactions", post(react_core_message))
        .route(
            "/conversations/{conversation_id}/records/{record}/thread/summary",
            post(summarize_thread),
        )
        .route("/sessions/{id}", axum::routing::patch(sessions::mode))
        .route("/sessions/{id}/presence", post(sessions::presence))
        .route(
            "/conversations/{conversation_id}/turns",
            post(create_core_conversation_turn),
        )
        .route(
            "/conversations/{conversation_id}/head",
            post(move_core_head),
        )
        .route(
            "/conversations/{conversation_id}/migrate-dag",
            post(migrate_core_dag),
        )
        .route(
            "/turns/{turn_id}/sub-sessions",
            post(spawn_core_sub_session),
        )
        .route(
            "/conversations/{conversation_id}/summaries",
            post(mint_core_scope_summary),
        )
        .route(
            "/summaries/{summary_id}/rederive",
            post(rederive_core_scope_summary),
        )
        .route("/turns/annotate", post(annotate_turn_vad))
        .route("/surface-events", post(submit_core_surface_event))
        .route_layer(middleware::from_fn_with_state(
            idempotency.clone(),
            idempotency_middleware,
        ));
    let core_routes = Router::new()
        // A consumed approval must never replay a cached 200, even with an idempotency key.
        .route("/consent/widen/accept", post(core_accept_widen))
        .route("/org-admin/{org}/powers", get(org_admin::powers))
        .route("/query", post(core_query))
        .route("/context-pack", post(core_context_pack))
        // Only a hydration that records its TURN's board is a keyed mutation.
        .route(
            "/context-board",
            post(context_board_hydrate).route_layer(middleware::from_fn_with_state(
                idempotency.clone(),
                board_turn_idempotency,
            )),
        )
        .route(
            "/context-board/turns/{turn}",
            get(context_board_turn_history),
        )
        .route("/explain/memory/{entity}", get(core_explain_memory))
        .route("/explain/gate/{receipt}", get(core_explain_gate))
        .route("/context-board/scratchpad", post(context_board_scratchpad))
        .route(
            "/context-board/scratchpad/recall",
            post(context_board_scratchpad_recall),
        )
        .route("/hydrate", post(core_hydrate))
        .route("/batch/shortId/hydrate", post(core_batch_short_id_hydrate))
        .route("/run-tree", get(core_run_tree))
        .route("/run-tree/observe", get(core_run_tree_observe))
        .route("/run-tree/intervene", post(core_run_tree_intervene))
        .route("/memory/{id}/timeline", get(core_memory_timeline))
        .route(
            "/memory/{id}/watch",
            get(memory::core_memory_watch_read)
                .put(memory::core_memory_watch_enable)
                .delete(memory::core_memory_watch_disable),
        )
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
            "/conversations/{conversation_id}/members",
            get(conversation_members::read_members),
        )
        .route(
            "/conversations/{conversation_id}/records",
            get(get_core_dag),
        )
        .route(
            "/conversations/{conversation_id}/records/{record}/thread",
            get(get_thread),
        )
        .route(
            "/conversations/{conversation_id}/canonical",
            get(get_canonical),
        )
        .route(
            "/conversations/{conversation_id}/turns",
            get(list_core_conversation_turns),
        )
        .route(
            "/conversations/{conversation_id}/transcript",
            get(conversation_transcript::get_core_conversation_transcript),
        )
        .route(
            "/conversations/{conversation_id}/scope",
            post(resolve_core_scope),
        )
        .route("/turns/{turn_id}/sub-sessions", get(list_core_sub_sessions))
        .route(
            "/summaries/{summary_id}/covers",
            get(get_core_summary_covers),
        )
        .route("/summary-attempts/{attempt}", get(get_core_summary_status))
        .route(
            "/summaries/{summary_id}/derivation",
            get(get_core_summary_metadata),
        )
        .route("/summary-purposes", get(list_core_summary_purposes))
        .route("/claims/{claim_id}/drill", get(drill_core_header))
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
        .route(
            "/access-grants/{grant_id}/revoke",
            post(revoke_companion_access_grant),
        )
        .route_layer(middleware::from_fn_with_state(
            idempotency,
            idempotency_middleware,
        ));
    let companion_routes = Router::new()
        .route("/profiles", get(list_profiles))
        .route("/personas/access-requests", get(list_access_requests))
        .route(
            "/profiles/{person_ref}",
            get(get_companion_profile).post(refresh_companion_profile),
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
        .route("/.well-known/oneiron", get(pairing::descriptor))
        .route("/v1/core/pairing/links", post(pairing::create_link))
        .route("/v1/core/pairing/redeem", post(pairing::redeem))
        .route("/v1/core/pairing/oauth", post(pairing::oauth_exchange))
        .route("/v1/core/slips/revoke", post(pairing::revoke))
        .route(
            "/v1/core/authority/checkpoints/{id}",
            get(authority_checkpoint::bundle),
        )
        .merge(artifact_routes())
        // ONE-1704: two SEPARATELY REGISTERED MCP endpoints, each pinned to one
        // immutable surface mode by its route entry. Nothing on the wire moves a
        // connection between them.
        //
        // Each endpoint's registered surface is its WHOLE callable surface: no
        // retired `oneiron.*` plain-verb name resolves on either route.
        //
        // Registration reflects this server's verified host binding. A bound
        // QuickJS provider enables durable execute_code on both endpoints;
        // without one, admission returns code_host_unbound before any run.
        .route("/mcp", post(mcp_gateway))
        .route("/mcp/tool-first", post(mcp_tool_first_gateway))
        .route("/api/core/discover", get(discover))
        .route("/api/search/vector", get(search_vector))
        .route("/api/search/semantic", post(search_semantic))
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
        .merge(self::esign::editor_routes())
        .merge(self::blob_artifacts::routes())
        // ONE-1908: git smart-HTTP. Stock clients clone, fetch, and push here;
        // every route streams through one `git http-backend` child.
        .merge(self::git_http::git_http_routes())
        .nest("/v1/llm", self::llm::routes())
        .merge(self::openai_proxy::routes())
        .nest("/v1/ai", self::ai::routes())
        .nest("/v1/core", core_routes)
        // ONE-1441: the facade projection is its own nest, not an arm inside
        // `core_routes`. Nesting expands each row into a concrete
        // `/v1/core/facade/<verb>` path, so it neither shadows nor is shadowed
        // by the storage-shaped `/v1/core` routes above, and its 64 MiB body
        // limit stays a property of this nest alone.
        .nest(
            "/v1/core/facade",
            self::facade::recorded_facade_routes(server.clone()),
        )
        // OF-181: the app's one action layer, for its buttons and its agents.
        .merge(self::facade::action_routes::routes())
        // OF-181: a host-rendered lens card's events and close, on its held frame.
        .merge(self::facade::ui_action_routes::routes())
        .nest("/v1/companion", companion_routes)
        .nest("/v1/owner", self::owner_routes::routes())
        .merge(self::operator_routes::routes())
        // OF-158: a removed member's own leave notices, on its revoked slip.
        .merge(crate::auth::left_notice_routes())
        .merge(self::report::routes())
        // OF-495: an agent role holder's skill tradeoff asks and picks.
        .merge(self::facade::role_picks::routes())
        // OF-516: a role holder's door to the ladder's person asks.
        .merge(self::facade::decision_role_asks::routes())
        .route("/v1/usage/events", post(record_usage_event))
        .route(
            "/v1/usage/owners/{owner}/vaults/{vault_id}/rollup",
            get(get_usage_rollup),
        )
        .merge(legacy_mutation_routes)
        // Config-only CIMD documents remain public before OAuth bootstrap.
        .route("/oauth/client/native.json", get(client_metadata::native))
        .route("/oauth/client/web.json", get(client_metadata::web))
        // The public ceremony bypasses the hosted device lease but retains
        // matched-route wire receipts and threshold questions.
        .merge(self::esign::public_routes())
        // OF-519: the served built-in channels' provider webhooks. Keyless;
        // the provider's HMAC over the raw body authenticates each one.
        .merge(crate::builtin_host::routes())
        .layer(middleware::from_fn_with_state(
            server.clone(),
            crate::wire_telemetry::observe_http,
        ))
        // Published anonymous booking capabilities validate a live owner publication
        // and scoped tokens; they do not authorize access to private vault routes.
        .merge(self::booking::public_booking_router())
        // The open feedback inbox: keyless, and mounted only when its
        // config section turns it on (ARCH-0056 #open-inbox).
        .merge(self::feedback_inbox::routes(&server))
        // OF-273: a former peer's signed courtesy deletion ask and answer.
        // Keyless; the signed body authenticates against the pinned pact key.
        .merge(self::cooperative_deletion::routes())
        // ARCH-0052 D5: everyone in a room keeps their own copy of an
        // off-record talk. Its own nest, outside the idempotency layer and
        // the wire receipts: nothing of the stretch may outlive it. The
        // owner's own off-record routes sit out here for the same reason.
        // Anonymous turns also keep no wire or idempotency receipt, and say so.
        .merge(
            self::anonymous_chat::routes()
                .layer(middleware::map_response(call_receipt::no_record_reply)),
        )
        // OF-538's one exception: these replies carry no call receipt, and
        // say so (`x-oneiron-receipt-ref: none; no-record`).
        .nest(
            "/v1/core/off-record",
            self::off_record_rooms::routes()
                .layer(middleware::map_response(call_receipt::no_record_reply)),
        )
        .nest(
            "/v1/owner",
            self::owner_routes::off_record_routes()
                .layer(middleware::map_response(call_receipt::no_record_reply)),
        )
        .with_state(server.clone())
        // OF-604: inside admission, outside every route and pre-reader, so
        // digests and body limits see the decoded bytes.
        .layer(middleware::from_fn(self::body_codec::body_codec))
        .layer(middleware::from_fn_with_state(
            server.clone(),
            crate::auth::admit_http_binding,
        ))
        // FIX 811: outside the binding door, so a reply that reached no
        // door's receipt is still its connection's.
        .layer(middleware::from_fn_with_state(
            server,
            call_receipt::connection_receipt,
        ))
}

/// The `/a/` routes, which the API and the artifact-only listener both serve.
fn artifact_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/a/{artifact}", get(serve_artifact_root))
        .route("/a/{artifact}/", get(serve_artifact_root))
        .route("/a/{artifact}/{*path}", get(serve_artifact_path))
}

/// The artifact-only listener's router: this vault's `/a/`, and under each
/// configured artifact domain, this vault at its own subdomain
/// (`<vault>.<domain>/<artifact>/…`). No API route is reachable on it.
pub(crate) fn artifact_app(server: Arc<SyncServer>) -> Router {
    let local = vault_artifact_app(server.clone());
    let mut hosts = ArtifactHosts::new(&server.config.artifact_domains);
    if let Some(name) = server.config.artifact_vault_name.as_deref() {
        hosts = hosts.with_vault_app(name, local.clone());
    }
    hosts.into_app(local)
}

/// One vault's artifact routes: `/a/` and nothing else, on an origin of its
/// own. It keeps the API's wire receipts and its binding admission, which
/// spends each holder proof's nonce, so a member's proof replays on neither
/// listener.
pub(crate) fn vault_artifact_app(server: Arc<SyncServer>) -> Router {
    artifact_routes()
        .layer(axum::Extension(self::artifacts::ArtifactOnlyListener))
        .layer(middleware::from_fn_with_state(
            server.clone(),
            crate::wire_telemetry::observe_http,
        ))
        .with_state(server.clone())
        .layer(middleware::from_fn_with_state(
            server,
            crate::auth::admit_http_binding,
        ))
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
                    "capabilities": ["core.discover", "skills_pack.fetch", "search.vector", "search.semantic", "search.text"],
                    "modes": ["flash", "thinking", "pro", "ultra"]
                },
                "formats": ["json", "yaml", "toon", "markdown", "plaintext"],
                "rate_limit": {
                    "api_enforced": false,
                    "websocket_enforced": false,
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
                },
                "ai": {
                    "dreamer": "idle",
                    "dreamer_reason": "no_model_configured",
                    "compaction": "off",
                    "compaction_reason": "no_model_configured"
                }
            })
        )
    )
)]
async fn health(State(server): State<Arc<SyncServer>>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        service: "oneiron-server",
        capabilities: feature_flags(&server),
        formats: supported_formats(),
        rate_limit: rate_limit_status(&server.config),
        runtime: runtime_health_status_for_config(&server.config),
        ai: server.ai.status().health(),
        artifact_port: server.artifact_port(),
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
    /// Background AI state, redacted: states and reasons, never model names.
    ai: crate::ai_host::AiHealth,
    /// The port on this host whose origin serves `/a/` with nothing else
    /// beside it. Open artifacts there: on the API's origin a code bundle is
    /// sandboxed, and its module scripts and fonts do not load. Absent where
    /// no artifact listener serves.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 49152)]
    artifact_port: Option<u16>,
}

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

// ─── Context Pack ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
