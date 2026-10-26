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
// FIX 8238: an answer's resources kept until the answer is encoded.
pub(crate) mod answer_hold;
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
mod core;
mod courtesy_delete;
use self::courtesy_delete as cooperative_deletion;
mod discover;
mod entity;
mod error_map;
mod esign;
pub(crate) use self::esign::delivery_outbox::spawn as spawn_esign_delivery_outbox;
pub(crate) use self::esign::hold_worker::spawn as spawn_esign_hold_worker;
pub(crate) use self::esign::hold_worker::spawn_admitted as spawn_esign_hold_worker_admitted;
pub(crate) use self::esign::notice_worker::dispatch_due_notices as dispatch_esign_due_notices;
#[cfg(unix)]
pub(crate) use self::esign::seal_worker::SealConfig as EsignSealConfig;
#[cfg(unix)]
pub(crate) use self::esign::seal_worker::spawn as spawn_esign_seal_worker;
#[cfg(unix)]
pub(crate) use self::esign::seal_worker::spawn_admitted as spawn_esign_seal_worker_admitted;
mod off_record_rooms;
mod org_admin;
mod pairing;
// FIX 922: the kit door to the sealed cloud bundle.
mod recovery_bundle;
mod sessions;
mod slip_renewal;
// ONE-1441 [WIRE-P1]: the bounded HTTP projection of the engine memory
// surface, nested at `/v1/core/facade`. Its own file because it is its own
// contract — one route per public verb, engine DTOs verbatim, and a facade
// error envelope whose `code` is the engine's raw string rather than this
// crate's closed `ErrorCode`.
mod facade;
// FIX 2222: who a host credential acts as at every door, through one resolver.
pub(crate) mod host_action;
// OF-489: the held socket runs every facade verb through the facade's one
// generated dispatch, under the credential its connection bound, and claims
// the invocation a call names as the HTTP facade does (FIX 2059).
pub(crate) use self::facade::{
    AsrSessions, DoorClaim, FacadeApiError, FacadeCall, INVOCATION_CONFLICT, INVOCATION_IN_FLIGHT,
    ModelStreams, admission_observer, ai_speech_for_run, call_verb as facade_call_verb,
    claim_door_invocation, connector_answer_as, connector_call_listing_as, invocation_body,
    self_use_as,
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
// FIX 9382: a caller's own push of one TASK to Linear now.
mod linear_push;
mod llm;
#[cfg(feature = "mesh")]
pub(crate) use llm::MeshLlm;
mod mcp_gateway;
mod memory;
// ONE-207 [RET-207]: the provider-neutral memory reasoning route. It owns the
// depth cost gate, the extractive answer for the model-free tiers, and the
// citation gate over whatever a host composer returns.
pub(crate) mod memory_reason;
// FIX 365: the result a MESSAGE carries, read on its transcript's read lane.
mod message_result;
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
// FIX 5911: an owner's own program proves its waking person the live
// recorded owner, and takes the owner's media and hook-replay doors.
pub(crate) use self::facade::{
    ai_media_as_owner, ai_video_as_owner, ai_video_cancel_as_owner, ai_video_poll_as_owner,
    vault_hooks_replay_as_owner,
};
pub(crate) use owner_routes::managed_owner_proof;
mod packs;
mod params;
// ONE-1437: in-process local reactive read contract. No HTTP surface by design
// (the ONE-1925 client-framework binding and the ONE-1495 cloud carrier are its
// consumers), so the non-test build sees a contract with no caller — the
// `protocol::close_codes` posture.
pub(crate) mod call_receipt;
mod context_board;
pub(crate) use context_board::{action_board, freeze_chat_context, record_action_answer};
#[allow(dead_code)]
mod reactive;
mod report;
mod routes;
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
pub(crate) use self::routes::api_routes;
pub(crate) use self::run_tree::*;
use self::scoped_auth::{check_api_auth, scoped_read_for_legacy_api};
pub(crate) use self::scoped_auth::{
    credential_memory, credential_read_key, mcp_credential_memory, require_live_managed_owner,
    scoped_read_for_core_auth,
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

/// The `/a/` routes, which the API and the artifact-only listener both serve.
fn artifact_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/a/{artifact}", get(serve_artifact_root))
        .route("/a/{artifact}/", get(serve_artifact_root))
        .route("/a/{artifact}/{*path}", get(serve_artifact_path))
}

/// The artifact-only listener's router: this vault's `/a/`, and under each
/// configured artifact domain, this vault at its own subdomain
/// (`<vault>.<domain>/<artifact>/…`). A managed vault answers on its internal
/// authority instead (`<vault_id>.artifact.invalid/<artifact>/…`, FIX 6716)
/// and reads no artifact domain. No API route is reachable on it.
pub(crate) fn artifact_app(server: Arc<SyncServer>) -> Router {
    let local = vault_artifact_app(server.clone());
    let hosts = if let Some(vault_id) = server.config.artifact_internal_vault_id.as_deref() {
        ArtifactHosts::internal().with_vault_app(vault_id, local.clone())
    } else {
        let mut hosts = ArtifactHosts::new(&server.config.artifact_domains);
        if let Some(name) = server.config.artifact_vault_name.as_deref() {
            hosts = hosts.with_vault_app(name, local.clone());
        }
        hosts
    };
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
            description = "Server is reachable and returns its modes, a summary of its capabilities (counts per family and the digest of the full set authenticated discovery lists), formats, and rate-limit settings.",
            body = HealthResponse,
            content_type = "application/json",
            example = json!({
                "status": "ok",
                "service": "oneiron-server",
                "modes": ["flash", "thinking", "pro", "ultra"],
                "capabilities": {
                    "total": 2228,
                    "digest": "blake3:5f0c8a1d2e3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5",
                    "counts": {"booking": 5, "core": 14, "mcp.endpoint.primary": 2, "mcp.endpoint.tool_first": 1091, "mcp.tool": 15, "mcp.tool.vault": 920, "search": 3, "self": 10}
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
        modes: CAPABILITY_MODES.to_vec(),
        capabilities: feature_flags(&server).summary(),
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
    /// Model or runtime effort modes advertised by the API.
    #[schema(value_type = Vec<String>, example = json!(["flash", "thinking", "pro", "ultra"]))]
    modes: Vec<&'static str>,
    /// How many capabilities each family holds and the digest of the full
    /// set, which authenticated `/api/core/discover` lists by family.
    capabilities: CapabilitySummary,
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
