//! HTTP query routes for web dashboard access.
//!
//! These routes provide server-side query capabilities for clients
//! that don't have a local LMDB vault (e.g., web dashboard).
//!
//! Auth: shared secret header for Phase 1.

use crate::auth::CoreAuth;
use crate::auth::require_owner_auth;
#[cfg(test)]
use crate::config::SyncServerConfig;
use crate::error::ApiError;
use crate::error::ApiErrorDetails;
use crate::error::ApiErrorEnvelope;
use crate::error::ErrorCode;
use crate::idempotency::IdempotencyLayerState;
use crate::idempotency::idempotency_middleware;
use crate::projection::View;
use crate::protocol::CountMode;
use crate::protocol::PaginatedResponse;
use crate::protocol::ResponseMeta;
use crate::runtime::RuntimeHealthStatus;
use crate::runtime::RuntimeMode;
use crate::runtime::RuntimeProviderKind;
use crate::runtime::RuntimeRole;
use crate::runtime::RuntimeRoute;
use crate::runtime::RuntimeRouteProvenance;
use crate::runtime::RuntimeRouteReason;
use crate::runtime::RuntimeRouteSource;
use crate::runtime::RuntimeRouteState;
use crate::runtime::RuntimeStatus;
use crate::server::SyncServer;
use crate::skills_pack as skills_pack_artifact;
use crate::usage::ConsumerAllowanceState;
use crate::usage::ConsumerAllowanceWarning;
use crate::usage::ConsumerAllowanceWarningLevel;
use crate::usage::ConsumerTopUp;
use crate::usage::ConsumerTopUpRequest;
use crate::usage::ConsumerTopUpState;
use crate::usage::ConsumerUsageDetails;
use crate::usage::ConsumerUsageState;
use crate::usage::UsageEvent;
use crate::usage::UsageRecordResult;
use crate::usage::UsageRollup;
use axum::Router;
#[cfg(test)]
use axum::body::Bytes;
use axum::extract::Query;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::extract::rejection::QueryRejection;
use axum::http::HeaderMap;
#[cfg(test)]
use axum::http::header::CACHE_CONTROL;
#[cfg(test)]
use axum::http::header::CONTENT_SECURITY_POLICY;
use axum::http::header::CONTENT_TYPE;
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
use oneiron::ErrorKind;
#[cfg(test)]
use oneiron::registry::ENTITY_TYPE_MESSAGE;
#[cfg(test)]
use oneiron::registry::ENTITY_TYPE_TURN;
use serde::Deserialize;
use serde::Serialize;
#[cfg(test)]
use serde_json::json;
#[cfg(test)]
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use utoipa::IntoParams;
use utoipa::OpenApi;
use utoipa::ToSchema;

mod artifacts;
mod companion;
mod consumer_usage;
mod context_pack;
mod conversations;
mod core;
mod discover;
mod entity;
mod lease;
mod mcp_gateway;
mod memory;
mod openapi;
mod resume;
mod run_tree;
mod search;
mod surface_events;
mod vad;

pub(crate) use self::artifacts::*;
pub(crate) use self::companion::*;
pub(crate) use self::consumer_usage::*;
pub(crate) use self::context_pack::*;
pub(crate) use self::conversations::*;
pub(crate) use self::core::*;
pub(crate) use self::discover::*;
pub(crate) use self::entity::*;
pub(crate) use self::lease::*;
pub(crate) use self::mcp_gateway::*;
pub(crate) use self::memory::*;
pub(crate) use self::openapi::*;
pub(crate) use self::resume::*;
pub(crate) use self::run_tree::*;
pub(crate) use self::search::*;
pub(crate) use self::surface_events::*;
pub(crate) use self::vad::*;

const API_LEVEL: &str = "v1";
// ONE-214 is read-only and adds no notification-specific storage. Keep resume
// hydration bounded by returning pending notifications from a latest window.

#[derive(OpenApi)]
#[openapi(
    paths(
        openapi_json,
        skills_pack,
        health,
        discover,
        search_vector,
        search_text,
        get_entity,
        get_edges,
        core_batch,
        core_query,
        core_hydrate,
        core_batch_short_id_hydrate,
        core_memory_timeline,
        core_memory_verb,
        list_core_outbound_capabilities,
        get_core_outbound_capability,
        get_core_outbound_verb_contract,
        core_context_pack,
        core_run_tree,
        core_run_tree_observe,
        core_run_tree_intervene,
        submit_core_surface_event,
        get_core_surface_event,
        list_core_conversations,
        create_core_conversation,
        list_core_conversation_turns,
        create_core_conversation_turn,
        get_core_turn,
        annotate_turn_vad,
        read_turn_vad_annotation,
        create_companion_access_grant,
        revoke_companion_access_grant,
        get_companion_profile,
        refresh_companion_profile,
        create_companion_register_record,
        get_companion_register_record,
        update_companion_register_record,
        retire_companion_register_record,
        end_companion_register_relationship,
        record_usage_event,
        get_usage_rollup,
        get_consumer_usage,
        get_consumer_usage_details,
        top_up_consumer,
        lease_revoke
    ),
    components(schemas(
        CountMode,
        PaginatedResponse<SearchResult>,
        ResponseMeta,
        View,
        HealthResponse,
        DiscoverResponse,
        SkillPackDiscovery,
        BoundContext,
        DiscoveredEntity,
        FeatureFlags,
        OutboundCapabilityDiscovery,
        OutboundConnectorManifestSummary,
        RateLimitStatus,
        RuntimeMode,
        RuntimeProviderKind,
        RuntimeRole,
        RuntimeRoute,
        RuntimeRouteProvenance,
        RuntimeRouteReason,
        RuntimeRouteSource,
        RuntimeRouteState,
        RuntimeStatus,
        ApiError,
        ApiErrorEnvelope,
        ApiErrorDetails,
        ErrorCode,
        VectorSearchQuery,
        SearchResult,
        TextSearchQuery,
        EdgeResult,
        CoreBatchRequest,
        CoreBatchEntityInput,
        CoreBatchEntityResult,
        CoreBatchResponse,
        CoreRunTreeQuery,
        CoreRunTreeInterventionRequest,
        CoreRunTreeInterventionKind,
        CoreRunTreeInterventionResponse,
        CoreRunTreeInterventionEffect,
        CoreRunTreeResponse,
        CoreRunTreeNode,
        CoreRunTreeStatus,
        CoreRunTreeTimestamps,
        CoreRunTreeFailure,
        CoreRunTreeEvent,
        CoreRunTreeEventKind,
        CoreRunTreeRepair,
        SurfaceEventSubmitRequest,
        SurfaceEventSourcePayload,
        SurfaceSourceAppPayload,
        SurfaceEventActionPayload,
        SurfaceInteractionKindPayload,
        SurfaceCounterpartyPayload,
        SurfaceEventAckResponse,
        SurfaceEventRejectionResponse,
        SurfaceEventStatusResponse,
        SurfaceEventHandoffStatePayload,
        CoreTextField,
        CoreQueryRequest,
        CoreHydrateRequest,
        CoreHydrateResponse,
        CoreHydrateStatus,
        CoreHydrateDeletionMetadata,
        CoreHydrateDeletionSource,
        CoreHydrateDeletionReason,
        CoreBatchShortIdHydrateRequest,
        CoreBatchShortIdHydrateResponse,
        CoreBatchShortIdHydrateItem,
        CoreShortIdHydrateOutcome,
        CoreShortIdHydrateError,
        CoreShortIdHydrateErrorKind,
        CoreMemoryTimelineResponse,
        CoreMemoryTimelineRecord,
        CoreMemoryTimelineRecordState,
        CoreMemoryVerbRequest,
        CoreMemoryVerbResponse,
        CoreMemoryVerbDeleteOutcome,
        CoreMemoryVerbDeleteReason,
        CoreMemoryOperationKind,
        ContextPackDepthControls,
        ContextPackPolicyControls,
        ContextPackTimeControls,
        ContextPackRetrievalBudgetControls,
        ContextPackBudgetControls,
        EiriMemoryBoardControls,
        EiriMemoryBoardSlotControls,
        EiriSessionRagControls,
        EiriCompanionControls,
        CoreContextPackRequest,
        CoreContextPackResponse,
        CoreEiriCompanionAssembly,
        CoreEiriMemoryBoard,
        CoreEiriMemoryBoardBudget,
        CoreEiriMemoryBoardRow,
        CoreEiriMemoryBoardSlot,
        CoreEiriMemoryBoardSource,
        CoreEiriSessionRagState,
        CoreContextEntity,
        CoreContextEdge,
        CoreContextPackStats,
        CoreContextPackItemAccounting,
        CoreContextPackState,
        CoreContextPackStateKind,
        CoreContextPackStateReason,
        CoreContextPackScoreComponent,
        CoreContextPackScoreEvidence,
        CoreContextPackEvidence,
        CoreListQuery,
        CoreCreateEntityRequest,
        CoreCreateTurnRequest,
        CoreEntityWriteResponse,
        VadPayload,
        TurnVadAnnotationSource,
        TurnVadAnnotateRequest,
        TurnVadAnnotateQuery,
        TurnVadAnnotateResponse,
        CompanionAccessGrantScopePayload,
        CompanionAccessGrantResponse,
        CompanionCreateAccessGrantRequest,
        CompanionRevokeAccessGrantRequest,
        CompanionProfileAccess,
        CompanionProfileConfidencePayload,
        CompanionProfileDriftAnchor,
        CompanionProfileNextAction,
        CompanionProfilePayload,
        CompanionProfileRefreshRequest,
        CompanionProfileResponse,
        CompanionProfileStaleReasonPayload,
        CompanionRegisterScopePayload,
        CompanionRegisterRelationshipRefPayload,
        CompanionRegisterSubjectPayload,
        CompanionRegisterProvenancePayload,
        CompanionRegisterRecordPayload,
        CompanionRegisterCreateRecordRequest,
        CompanionRegisterUpdateRecordRequest,
        CompanionRegisterRetireRecordRequest,
        CompanionEndRelationshipRequest,
        CompanionGoodbyeArtifactHookPayload,
        CompanionEndRelationshipResponse,
        CompanionRegisterRecordResponse,
        LeaseRevokeRequest,
        LeaseRevokeResponse,
        ConsumerAllowanceState,
        ConsumerAllowanceWarning,
        ConsumerAllowanceWarningLevel,
        ConsumerTopUp,
        ConsumerTopUpRequest,
        ConsumerTopUpState,
        ConsumerUsageDetails,
        ConsumerUsageState,
        UsageEvent,
        UsageRecordResult,
        UsageRollup
    )),
    info(
        title = "Oneiron Server API",
        version = "0.1.0",
        description = "Local Oneiron sync daemon HTTP API for search, entity reads, context-pack requests, and lease recovery."
    )
)]
pub(crate) struct ApiDoc;

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
        .merge(companion_mutation_routes);

    Router::new()
        .route("/api/openapi.json", get(openapi_json))
        .route("/api/skills/oneiron.skills.md", get(skills_pack))
        .route("/api/health", get(health))
        .route("/a/{artifact}", get(serve_artifact_root))
        .route("/a/{artifact}/", get(serve_artifact_root))
        .route("/a/{artifact}/{*path}", get(serve_artifact_path))
        .route("/mcp", post(mcp_gateway))
        .route("/api/core/discover", get(discover))
        .route("/api/search/vector", get(search_vector))
        .route("/api/search/text", get(search_text))
        .route("/api/entity/{id}", get(get_entity))
        .route("/api/edges/{id}", get(get_edges))
        .nest("/v1/core", core_routes)
        .nest("/v1/companion", companion_routes)
        .route("/api/companion/resume", post(resume))
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

/// Gates the legacy `/api/*` routes on an owner-grade bearer.
///
/// These routes read the whole vault under one actor ref, so they stay a
/// trust-root surface: scoped `/v1` delegation tokens do not reach them.
fn check_api_auth(headers: &HeaderMap, server: &SyncServer) -> Result<(), ApiError> {
    require_owner_auth(headers, &server.config, server.vault().as_ref()).map(drop)
}

const LEGACY_SCOPED_READ_ACTOR_REF: &str = "legacy-shared-secret";

fn scoped_read_for_core_auth<'a>(
    vault: &'a oneiron::Vault,
    auth: &CoreAuth,
) -> Result<oneiron::claim::ScopedRead<'a>, ApiError> {
    let actor_ref = auth.principal_ref().unwrap_or(auth.principal());
    scoped_read_for_actor_ref(vault, actor_ref)
}

fn scoped_read_for_legacy_api(
    vault: &oneiron::Vault,
) -> Result<oneiron::claim::ScopedRead<'_>, ApiError> {
    scoped_read_for_actor_ref(vault, LEGACY_SCOPED_READ_ACTOR_REF)
}

fn scoped_read_for_actor_ref<'a>(
    vault: &'a oneiron::Vault,
    actor_ref: &str,
) -> Result<oneiron::claim::ScopedRead<'a>, ApiError> {
    let actor_key = oneiron::claim::ScopedReadActorKey::new(actor_ref)
        .ok_or_else(|| ApiError::internal_server_error("scoped read actor key is empty"))?;
    Ok(vault.scoped_read(actor_key))
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

fn json_payload<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    let Json(payload) = payload.map_err(json_rejection_error)?;
    Ok(payload)
}

fn json_rejection_error(_rejection: JsonRejection) -> ApiError {
    ApiError::bad_request("invalid JSON request body", None)
}

fn has_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| {
            let media_type = media_type.trim();
            media_type.eq_ignore_ascii_case("application/json")
                || media_type.to_ascii_lowercase().ends_with("+json")
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

// ─── Companion resume ────────────────────────────────────────────────────────

// ─── Usage Ledger ────────────────────────────────────────────────────────────

// ─── Search Routes ────────────────────────────────────────────────────────────

fn default_limit() -> usize {
    10
}

// ─── Entity Routes ────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ViewQuery {
    /// Optional projection view. Entity reads default to `standard`; edge reads default to `summary`.
    #[schema(example = "standard")]
    #[param(example = "standard")]
    view: Option<View>,
}

// ─── Core API parity routes ─────────────────────────────────────────────────

fn parse_optional_entity_id(
    value: Option<&str>,
    field: &'static str,
) -> Result<oneiron::EntityId, ApiError> {
    value.map_or_else(
        || Ok(oneiron::EntityId::now()),
        |value| parse_entity_id_param(value, field),
    )
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn core_engine_error(message: &'static str, error: oneiron::Error) -> ApiError {
    match error.kind() {
        ErrorKind::DimensionMismatch
        | ErrorKind::InvalidVector
        | ErrorKind::InvalidKey
        | ErrorKind::InvalidConfig
        | ErrorKind::InvalidTemporalExpression
        | ErrorKind::InvalidEntityType
        | ErrorKind::InvalidTimeRange
        | ErrorKind::InvalidClaimBody
        | ErrorKind::InvalidAccessGrantBody
        | ErrorKind::InvalidCounterpartyContactBody
        | ErrorKind::InvalidCommRecordBody
        | ErrorKind::InvalidTaskBody
        | ErrorKind::InvalidCodeArtifactBody
        | ErrorKind::InvalidBlobArtifactBody
        | ErrorKind::InvalidEditManifest
        | ErrorKind::InvalidSkillBody
        | ErrorKind::InvalidCodebaseSnapshotBody
        | ErrorKind::InvalidCodeSymbolManifestBody
        | ErrorKind::InvalidAttemptQueueRecord
        | ErrorKind::InvalidAttemptQueueTransition
        | ErrorKind::MaintenanceKindNotWritable
        | ErrorKind::EntityTypeImmutable
        | ErrorKind::StructuralKindBandViolation
        | ErrorKind::StructuralKindCollision
        | ErrorKind::InvalidStructuralKindRegistration
        | ErrorKind::ClaimSelfSupersession
        | ErrorKind::ProvenanceClaimLifecycle
        | ErrorKind::AgentNotDispatchable
        | ErrorKind::InvalidAgentDispatchInput
        | ErrorKind::SystemAgentDisabled => ApiError::bad_request(error.to_string(), None),
        ErrorKind::EntityNotFound | ErrorKind::EdgeNotFound => ApiError::not_found("entity", None),
        ErrorKind::CycleDetected | ErrorKind::ChildOfCardinality => {
            ApiError::invalid_state(Some("child_of_constraint"))
        }
        ErrorKind::ClaimAlreadyClosed | ErrorKind::ProvenanceClaimAlreadyClosed => {
            ApiError::invalid_state(Some("memory_lifecycle_closed"))
        }
        ErrorKind::HostedMediaHashMatchKnownMatch => ApiError::new(
            error.to_string(),
            ApiErrorDetails::InvalidState {
                state: Some("hosted_media_hash_match_known_match".to_owned()),
            },
            [
                "Remove public access, preserve evidence, and follow the known-CSAM hosted media runbook.",
            ],
        ),
        ErrorKind::GateWriteRejected => ApiError::new(
            error.to_string(),
            ApiErrorDetails::InvalidState {
                state: Some("gate_write_rejected".to_owned()),
            },
            ["Route the write through policy review before retrying."],
        ),
        ErrorKind::GateConsentStale => ApiError::new(
            error.to_string(),
            ApiErrorDetails::InvalidState {
                state: Some("gate_consent_stale".to_owned()),
            },
            ["Restart policy review from the current diff and read frontier."],
        ),
        _ => ApiError::internal_server_error(message),
    }
}

// ─── Turn VAD annotation ─────────────────────────────────────────────────────

fn parse_entity_id_param(value: &str, field: &'static str) -> Result<oneiron::EntityId, ApiError> {
    oneiron::EntityId::from_hex(value).map_err(|_| {
        ApiError::bad_request(
            format!("{field} must be a 32-character hex entity id"),
            Some(field),
        )
    })
}

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

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

// ─── Lease revocation (ONE-1140, OD-8) ────────────────────────────────────────

// ─── Context Pack ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
