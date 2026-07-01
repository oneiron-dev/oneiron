//! HTTP query routes for web dashboard access.
//!
//! These routes provide server-side query capabilities for clients
//! that don't have a local LMDB vault (e.g., web dashboard).
//!
//! Auth: shared secret header for Phase 1.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header::CONTENT_TYPE};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::{Router, middleware};
use oneiron::{
    EdgeKind, ErrorKind, NotificationItem, ResumeBudget, ResumeBundle, SessionContext,
    UnprocessedItem, Vad, VadAnnotation, VadAnnotationSource,
    types::{
        ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_TURN,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::auth::{CoreAuth, CoreScope, check_auth};
use crate::config::SyncServerConfig;
use crate::error::{ApiError, ApiErrorDetails, ApiErrorEnvelope, EnvelopedApiError, ErrorCode};
use crate::idempotency::{IdempotencyLayerState, idempotency_middleware};
use crate::projection::{self, View};
use crate::protocol::{CountMode, PaginatedResponse, ResponseMeta};
use crate::runtime::{
    RuntimeHealthStatus, RuntimeMode, RuntimeProviderKind, RuntimeRole, RuntimeRoute,
    RuntimeRouteProvenance, RuntimeRouteReason, RuntimeRouteSource, RuntimeRouteState,
    RuntimeStatus,
};
use crate::server::SyncServer;
use crate::skills_pack as skills_pack_artifact;
use crate::usage::{
    ConsumerAllowanceState, ConsumerAllowanceWarning, ConsumerAllowanceWarningLevel, ConsumerTopUp,
    ConsumerTopUpRequest, ConsumerTopUpState, ConsumerUsageDetails, ConsumerUsageState, UsageError,
    UsageEvent, UsageMode, UsageRecordResult, UsageRollup,
};

const API_LEVEL: &str = "v1";
const SUPPORTED_FORMATS: &[&str] = &["json", "yaml", "toon", "markdown", "plaintext"];
const SKILL_PACK_NAME: &str = "oneiron-http-memory-api";
const SKILL_PACK_ENDPOINT: &str = "/api/skills/oneiron.skills.md";
const SKILL_PACK_FORMAT: &str = "agentskills.io";
const SKILL_PACK_MIME_TYPE: &str = "text/markdown";
const SKILL_PACK_LAYER_BOUNDARY: &str =
    "skills = how to think about memory; MCP tools = what to call";
const SKILL_PACK_LOAD_HINT: &str = "GET /api/skills/oneiron.skills.md from the same Oneiron HTTP origin before choosing memory search, read, context-pack, discovery, or recovery calls; use MCP tools as the callable layer.";
const SKILL_PACK_RESOLUTION: &str = "Resolve endpoint against the same origin used for /api/core/discover and send the configured x-oneiron-secret; do not resolve the pack against a local working directory.";
const EFFECTIVE_AUTH_SCOPES: &[&str] = &[
    "core:discover",
    "core:read",
    "core:write",
    "vault:read",
    "search:read",
    "entity:read",
    "turns:annotate",
    "companion:resume",
    "companion:profile:read",
    "companion:access-grant:write",
    "companion:register:read",
    "companion:register:write",
    "usage:read",
    "usage:write",
    "consumer:usage:read",
    "consumer:top-up:write",
    "sync:connect",
];
const CAPABILITIES: &[&str] = &[
    "core.discover",
    "core.batch",
    "core.query",
    "core.context_pack",
    "core.hydrate",
    "core.memory_timeline",
    "core.memory_verbs",
    "core.conversations",
    "core.turns",
    "health.capabilities",
    "skills_pack.fetch",
    "search.vector",
    "search.text",
    "entity.get",
    "edges.get",
    "turns.annotate",
    "context_pack",
    "companion.resume",
    "companion.profile",
    "companion.access_grants",
    "companion.register",
    "lease.revoke",
    "usage.event",
    "usage.rollup",
    "consumer.usage",
    "consumer.usage.details",
    "consumer.top_up",
];
const CAPABILITY_MODES: &[&str] = &["flash", "thinking", "pro", "ultra"];
// ONE-214 is read-only and adds no notification-specific storage. Keep resume
// hydration bounded by returning pending notifications from a latest window.
const RESUME_NOTIFICATION_LIMIT: usize = 128;
const RESUME_NOTIFICATION_SCAN_LIMIT: usize = 4096;
const CORE_MAX_BATCH_ENTITIES: usize = 256;
const CORE_MAX_LIST_LIMIT: usize = 1000;

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
        core_context_pack,
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
        create_companion_register_record,
        get_companion_register_record,
        update_companion_register_record,
        retire_companion_register_record,
        context_pack,
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
        CoreContextPackRequest,
        CoreContextPackResponse,
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
        CompanionProfileResponse,
        CompanionRegisterScopePayload,
        CompanionRegisterRelationshipRefPayload,
        CompanionRegisterSubjectPayload,
        CompanionRegisterProvenancePayload,
        CompanionRegisterRecordPayload,
        CompanionRegisterCreateRecordRequest,
        CompanionRegisterUpdateRecordRequest,
        CompanionRegisterRetireRecordRequest,
        CompanionRegisterRecordResponse,
        LeaseRevokeRequest,
        LeaseRevokeResponse,
        ContextPackRequest,
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
        .route_layer(middleware::from_fn_with_state(
            idempotency.clone(),
            idempotency_middleware,
        ));
    let core_routes = Router::new()
        .route("/query", post(core_query))
        .route("/context-pack", post(core_context_pack))
        .route("/hydrate", post(core_hydrate))
        .route("/batch/shortId/hydrate", post(core_batch_short_id_hydrate))
        .route("/memory/{id}/timeline", get(core_memory_timeline))
        .route("/conversations", get(list_core_conversations))
        .route(
            "/conversations/{conversation_id}/turns",
            get(list_core_conversation_turns),
        )
        .route("/turns/{turn_id}", get(get_core_turn))
        .route("/turns/annotate", get(read_turn_vad_annotation))
        .merge(core_mutation_routes);
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
            "/access-grants/{grant_id}/revoke",
            post(revoke_companion_access_grant),
        )
        .route_layer(middleware::from_fn_with_state(
            idempotency,
            idempotency_middleware,
        ));
    let companion_routes = Router::new()
        .route("/profiles/{persona_ref}", get(get_companion_profile))
        .route(
            "/register/records/{record_id}",
            get(get_companion_register_record),
        )
        .merge(companion_mutation_routes);

    Router::new()
        .route("/api/openapi.json", get(openapi_json))
        .route("/api/skills/oneiron.skills.md", get(skills_pack))
        .route("/api/health", get(health))
        .route("/api/core/discover", get(discover))
        .route("/api/search/vector", get(search_vector))
        .route("/api/search/text", get(search_text))
        .route("/api/entity/{id}", get(get_entity))
        .route("/api/edges/{id}", get(get_edges))
        .nest("/v1/core", core_routes)
        .nest("/v1/companion", companion_routes)
        // context-pack is POST since it takes a complex options body
        .route("/api/context-pack", post(context_pack))
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

/// Returns the generated OpenAPI document for the HTTP API.
#[utoipa::path(
    get,
    path = "/api/openapi.json",
    responses(
        (
            status = 200,
            description = "Generated OpenAPI 3.1 document for the HTTP API.",
            body = Object,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid `x-oneiron-secret` header.",
            body = ApiError,
            content_type = "application/json",
            example = json!({
                "code": "UNAUTHORIZED",
                "message": "unauthorized",
                "details": { "code": "UNAUTHORIZED" },
                "suggestions": ["set x-oneiron-secret to the configured shared secret"]
            })
        )
    )
)]
async fn openapi_json(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<Value>, ApiError> {
    check_api_auth(&headers, &server.config)?;
    Ok(Json(openapi_document()))
}

/// Returns the static agentskills.io-compatible Oneiron skill pack.
#[utoipa::path(
    get,
    path = "/api/skills/oneiron.skills.md",
    responses(
        (
            status = 200,
            description = "Static agentskills.io-compatible progressive-disclosure skill pack for the live HTTP API.",
            body = String,
            content_type = "text/markdown; profile=agentskills.io",
            example = "# Oneiron HTTP Memory API Skill Pack"
        ),
        (
            status = 401,
            description = "Missing or invalid `x-oneiron-secret` header.",
            body = ApiError,
            content_type = "application/json",
            example = json!({
                "code": "UNAUTHORIZED",
                "message": "request is not authorized",
                "details": { "code": "UNAUTHORIZED" },
                "suggestions": ["Send the configured x-oneiron-secret header and retry."]
            })
        )
    )
)]
async fn skills_pack(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Result<impl IntoResponse, ApiError> {
    check_api_auth(&headers, &server.config)?;
    Ok((
        [(CONTENT_TYPE, skills_pack_artifact::MEDIA_TYPE)],
        skills_pack_artifact::CONTENT,
    ))
}

fn openapi_document() -> Value {
    let mut spec = serde_json::to_value(ApiDoc::openapi()).expect("serialize generated OpenAPI");
    merge_error_components(&mut spec);
    add_security_scheme(&mut spec);
    mark_entity_response_as_binary(&mut spec);
    fill_schema_description_gaps(&mut spec);
    spec
}

fn merge_error_components(spec: &mut Value) {
    let Some(components) = spec.get_mut("components").and_then(Value::as_object_mut) else {
        return;
    };
    let schemas = components
        .entry("schemas")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .expect("OpenAPI schemas must be an object");
    let error_components = crate::error::openapi_error_components();
    let error_components = error_components
        .as_object()
        .expect("error components must be an object");
    for (name, schema) in error_components {
        schemas.insert(name.clone(), schema.clone());
    }
}

fn mark_entity_response_as_binary(spec: &mut Value) {
    if let Some(content) = spec
        .get_mut("paths")
        .and_then(Value::as_object_mut)
        .and_then(|paths| paths.get_mut("/api/entity/{id}"))
        .and_then(Value::as_object_mut)
        .and_then(|path_item| path_item.get_mut("get"))
        .and_then(Value::as_object_mut)
        .and_then(|operation| operation.get_mut("responses"))
        .and_then(Value::as_object_mut)
        .and_then(|responses| responses.get_mut("200"))
        .and_then(Value::as_object_mut)
        .and_then(|response| response.get_mut("content"))
        .and_then(Value::as_object_mut)
        .and_then(|content| content.get_mut("application/octet-stream"))
        .and_then(Value::as_object_mut)
    {
        content.insert(
            "schema".to_owned(),
            json!({
                "type": "string",
                "format": "binary",
            }),
        );
    }
}

fn fill_schema_description_gaps(spec: &mut Value) {
    set_schema_property_description(
        spec,
        "VectorSearchQuery",
        "view",
        "Optional projection view for returned items. Defaults to summary.",
    );
    set_schema_property_description(
        spec,
        "TextSearchQuery",
        "view",
        "Optional projection view for returned items. Defaults to summary.",
    );
    set_schema_property_description(
        spec,
        "CoreQueryRequest",
        "view",
        "Optional projection view for returned items. Defaults to summary.",
    );
    set_schema_property_description(
        spec,
        "CoreHydrateRequest",
        "view",
        "Optional projection view for the hydrated live entity. Defaults to full.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackRequest",
        "view",
        "Optional field profile for hydrated context-pack fields. Defaults to standard.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackRequest",
        "depth",
        "Optional nested edge-depth controls for context-pack assembly.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackRequest",
        "policy",
        "Optional nested ranking and projection policy controls.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackRequest",
        "time",
        "Optional time-window filters for context-pack retrieval.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackRequest",
        "budget",
        "Optional retrieval and serialization budget controls.",
    );
    set_schema_property_description(
        spec,
        "ContextPackDepthControls",
        "edge_hop",
        "Edge expansion depth for neighbor hydration.",
    );
    set_schema_property_description(
        spec,
        "ContextPackDepthControls",
        "max_neighbors",
        "Maximum neighbors to hydrate during edge expansion.",
    );
    set_schema_property_description(
        spec,
        "ContextPackPolicyControls",
        "hydrate",
        "Whether to include hydrated fields.",
    );
    set_schema_property_description(
        spec,
        "ContextPackPolicyControls",
        "include_edges",
        "Whether to include edge records in hydrated entities.",
    );
    set_schema_property_description(
        spec,
        "ContextPackPolicyControls",
        "include_vectors",
        "Whether to include stored vectors when present.",
    );
    set_schema_property_description(
        spec,
        "ContextPackPolicyControls",
        "view",
        "Field profile for hydrated fields.",
    );
    set_schema_property_description(
        spec,
        "ContextPackPolicyControls",
        "boost_recency_days",
        "Apply recency boost with the supplied half-life in days.",
    );
    set_schema_property_description(
        spec,
        "ContextPackPolicyControls",
        "boost_salience",
        "Apply salience boost.",
    );
    set_schema_property_description(
        spec,
        "ContextPackPolicyControls",
        "boost_confidence",
        "Apply confidence boost.",
    );
    set_schema_property_description(
        spec,
        "ContextPackPolicyControls",
        "boost_contiguity",
        "Apply contiguity boost.",
    );
    set_schema_property_description(
        spec,
        "ContextPackTimeControls",
        "since",
        "Keep entities learned at or after this Unix timestamp.",
    );
    set_schema_property_description(
        spec,
        "ContextPackTimeControls",
        "occurred_start",
        "Occurrence window start, inclusive.",
    );
    set_schema_property_description(
        spec,
        "ContextPackTimeControls",
        "occurred_end",
        "Occurrence window end, inclusive.",
    );
    set_schema_property_description(
        spec,
        "ContextPackTimeControls",
        "learned_start",
        "Learned-at window start, inclusive.",
    );
    set_schema_property_description(
        spec,
        "ContextPackTimeControls",
        "learned_end",
        "Learned-at window end, inclusive.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRetrievalBudgetControls",
        "claims",
        "Maximum claim entities.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRetrievalBudgetControls",
        "turns",
        "Maximum turn entities.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRetrievalBudgetControls",
        "summaries",
        "Maximum summary entities.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRetrievalBudgetControls",
        "facets",
        "Maximum facet entities.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRetrievalBudgetControls",
        "other",
        "Maximum other entities.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRetrievalBudgetControls",
        "selected_edges",
        "Edge-walk neighbor selection budget.",
    );
    set_schema_property_description(
        spec,
        "ContextPackBudgetControls",
        "token_budget",
        "Serialized token budget for downstream serialized packs.",
    );
    set_schema_property_description(
        spec,
        "ContextPackBudgetControls",
        "max_item_tokens",
        "Per-item token cap for context-pack serialization.",
    );
    set_schema_property_description(
        spec,
        "ContextPackBudgetControls",
        "max_field_chars",
        "Maximum field characters before serialization truncation.",
    );
    set_schema_property_description(
        spec,
        "ContextPackBudgetControls",
        "retrieval",
        "Per-kind retrieval item budgets before final truncation.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRequest",
        "query",
        "Optional text retrieval seed for context-pack assembly.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRequest",
        "query_vector",
        "Optional embedding vector retrieval seed.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRequest",
        "limit",
        "Maximum number of candidate entities to retrieve.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRequest",
        "maxItemTokens",
        "Per-item token cap for context-pack serialization.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRequest",
        "hydrate",
        "Whether to include hydrated fields.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRequest",
        "include_edges",
        "Whether to include edge records in hydrated entities.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRequest",
        "edge_hop",
        "Edge expansion depth for neighbor hydration.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRequest",
        "max_neighbors",
        "Maximum neighbors to hydrate during edge expansion.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRequest",
        "include_vectors",
        "Whether to include stored vectors when present.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRequest",
        "view",
        "Field profile for hydrated fields.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRequest",
        "depth",
        "Optional nested edge-depth controls for context-pack assembly.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRequest",
        "policy",
        "Optional nested ranking and projection policy controls.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRequest",
        "time",
        "Optional time-window filters for context-pack retrieval.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRequest",
        "budget",
        "Optional retrieval and serialization budget controls.",
    );
    set_schema_property_description(
        spec,
        "CoreListQuery",
        "view",
        "Optional projection view for returned entities. Defaults to summary.",
    );
    set_schema_property_description(
        spec,
        "CoreHydrateResponse",
        "item",
        "Projected live entity; omitted when the short ref resolves to a deleted entity.",
    );
    set_schema_property_description(
        spec,
        "CoreHydrateResponse",
        "deletion",
        "Deletion metadata when the short ref resolves to a deleted entity.",
    );
    set_schema_property_description(
        spec,
        "CoreHydrateDeletionMetadata",
        "reason",
        "Decoded tombstone reason, absent for legacy, malformed, or dangling deletion rows.",
    );
    set_schema_property_description(
        spec,
        "CoreBatchShortIdHydrateRequest",
        "view",
        "Optional projection view for live hydrate results. Defaults to full.",
    );
    set_schema_property_description(
        spec,
        "CoreBatchShortIdHydrateItem",
        "result",
        "Live or deleted hydrate payload when the input resolves.",
    );
    set_schema_property_description(
        spec,
        "CoreBatchShortIdHydrateItem",
        "error",
        "Typed per-input hydrate error for malformed or not-found refs.",
    );
    set_schema_property_description(
        spec,
        "CoreShortIdHydrateError",
        "field",
        "Request field that failed validation, when known.",
    );
    set_schema_property_description(
        spec,
        "CoreContextEdge",
        "vad",
        "Optional edge VAD payload for semantic edges.",
    );
    set_schema_property_description(
        spec,
        "CoreContextEntity",
        "fields",
        "Hydrated entity fields when requested.",
    );
    set_schema_property_description(
        spec,
        "CoreContextEntity",
        "edges",
        "Hydrated outbound edges when requested.",
    );
    set_schema_property_description(
        spec,
        "CoreContextEntity",
        "vector",
        "Stored vector when requested and present.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackResponse",
        "empty",
        "Structured empty-result context when no entities surface.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackResponse",
        "state",
        "Typed missing-data or low-confidence state.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackResponse",
        "evidence",
        "Retrieval telemetry evidence and score breakdown.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackState",
        "kind",
        "Stable state discriminator.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackState",
        "reason",
        "Empty-result reason when no entities surfaced.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackState",
        "total_in_scope",
        "Total records in scope when known.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackState",
        "hint",
        "Caller-facing hint from the retrieval layer.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackEvidence",
        "telemetry_persisted",
        "Whether the retrieval telemetry row was finalized.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackEvidence",
        "retrieval_run_id",
        "Retrieval telemetry run id when persistence succeeded.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackEvidence",
        "result_ids",
        "Surfaced result ids recorded in telemetry.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackEvidence",
        "scores",
        "Final score evidence recorded in telemetry.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackScoreEvidence",
        "result_id",
        "Hex entity id.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackScoreEvidence",
        "final_rank",
        "Final rank after context-pack hydration.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackScoreEvidence",
        "final_score",
        "Final fused score.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackScoreEvidence",
        "components",
        "Signal-level score components.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackScoreComponent",
        "signal",
        "Retrieval signal name.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackScoreComponent",
        "rank",
        "Rank within the signal.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackScoreComponent",
        "score",
        "Raw signal score.",
    );
    set_schema_property_description(
        spec,
        "CompanionRegisterSubjectPayload",
        "relationship_ref",
        "Source and target entity pair for relationship records.",
    );
    set_schema_property_description(
        spec,
        "CompanionRegisterRecordPayload",
        "scope",
        "Visibility and privacy scope for this register record.",
    );
    set_schema_property_description(
        spec,
        "CompanionRegisterRecordPayload",
        "subject",
        "Persona or relationship subject for this register record.",
    );
    set_schema_property_description(
        spec,
        "CompanionRegisterRecordPayload",
        "provenance",
        "Provenance stamp for this register record.",
    );
    set_schema_property_description(
        spec,
        "CompanionRegisterCreateRecordRequest",
        "record",
        "Typed companion register record envelope to create.",
    );
    set_schema_property_description(
        spec,
        "CompanionRegisterUpdateRecordRequest",
        "record",
        "Replacement record envelope; scope and subject must match the existing record.",
    );
    set_schema_property_description(
        spec,
        "CompanionRegisterRecordResponse",
        "record",
        "Typed companion register record envelope.",
    );
}

fn set_schema_property_description(
    spec: &mut Value,
    schema_name: &str,
    property_name: &str,
    description: &str,
) {
    if let Some(property) = spec
        .get_mut("components")
        .and_then(Value::as_object_mut)
        .and_then(|components| components.get_mut("schemas"))
        .and_then(Value::as_object_mut)
        .and_then(|schemas| schemas.get_mut(schema_name))
        .and_then(Value::as_object_mut)
        .and_then(|schema| schema.get_mut("properties"))
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut(property_name))
        .and_then(Value::as_object_mut)
    {
        property.insert("description".to_owned(), Value::from(description));
    }
}

fn add_security_scheme(spec: &mut Value) {
    let Some(components) = spec.get_mut("components").and_then(Value::as_object_mut) else {
        return;
    };
    components
        .entry("securitySchemes")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .expect("OpenAPI securitySchemes must be an object")
        .insert(
            "OneironSecret".to_owned(),
            json!({
                "type": "apiKey",
                "in": "header",
                "name": "x-oneiron-secret",
                "description": "Phase-1 shared secret required by protected API routes when unauthenticated development access is disabled."
            }),
        );
    components
        .entry("securitySchemes")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .expect("OpenAPI securitySchemes must be an object")
        .insert(
            "CoreBearer".to_owned(),
            json!({
                "type": "http",
                "scheme": "bearer",
                "description": "Scoped bearer token for canonical /v1/core/* and companion control-plane routes. The current local shell accepts the configured shared secret, optionally suffixed with ';scope=core:read,core:write,core:auth'."
            }),
        );

    let protected_operations = [
        ("/api/openapi.json", "get"),
        ("/api/skills/oneiron.skills.md", "get"),
        ("/api/core/discover", "get"),
        ("/api/search/vector", "get"),
        ("/api/search/text", "get"),
        ("/api/entity/{id}", "get"),
        ("/api/edges/{id}", "get"),
        ("/api/context-pack", "post"),
        ("/v1/consumer/usage", "get"),
        ("/v1/consumer/usage/details", "get"),
        ("/v1/consumer/top-up", "post"),
        ("/v1/usage/events", "post"),
        ("/v1/usage/tenants/{tenant_id}/rollup", "get"),
        ("/api/lease/revoke", "post"),
    ];
    for (path, method) in protected_operations {
        if let Some(operation) = spec
            .get_mut("paths")
            .and_then(Value::as_object_mut)
            .and_then(|paths| paths.get_mut(path))
            .and_then(Value::as_object_mut)
            .and_then(|path_item| path_item.get_mut(method))
            .and_then(Value::as_object_mut)
        {
            operation.insert("security".to_owned(), json!([{ "OneironSecret": [] }]));
        }
    }

    for (path, method) in [
        ("/v1/core/query", "post"),
        ("/v1/core/context-pack", "post"),
        ("/v1/core/hydrate", "post"),
        ("/v1/core/batch/shortId/hydrate", "post"),
        ("/v1/core/memory/{id}/timeline", "get"),
        ("/v1/core/memory/verbs/{verb}", "post"),
        ("/v1/core/conversations", "get"),
        ("/v1/core/conversations", "post"),
        ("/v1/core/conversations/{conversation_id}/turns", "get"),
        ("/v1/core/conversations/{conversation_id}/turns", "post"),
        ("/v1/core/turns/{turn_id}", "get"),
        ("/v1/core/batch", "post"),
        ("/v1/core/turns/annotate", "get"),
        ("/v1/core/turns/annotate", "post"),
        ("/v1/companion/access-grants", "post"),
        ("/v1/companion/access-grants/{grant_id}/revoke", "post"),
        ("/v1/companion/profiles/{persona_ref}", "get"),
        ("/v1/companion/register/records", "post"),
        ("/v1/companion/register/records/{record_id}", "get"),
        ("/v1/companion/register/records/{record_id}", "post"),
        ("/v1/companion/register/records/{record_id}/retire", "post"),
    ] {
        if let Some(operation) = spec
            .get_mut("paths")
            .and_then(Value::as_object_mut)
            .and_then(|paths| paths.get_mut(path))
            .and_then(Value::as_object_mut)
            .and_then(|path_item| path_item.get_mut(method))
            .and_then(Value::as_object_mut)
        {
            operation.insert(
                "security".to_owned(),
                json!([{ "CoreBearer": [] }, { "OneironSecret": [] }]),
            );
        }
    }
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
                    "max_update_payload_bytes": 1048576
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

fn json_payload<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    let Json(payload) = payload.map_err(json_rejection_error)?;
    Ok(payload)
}

fn json_rejection_error(_rejection: JsonRejection) -> ApiError {
    ApiError::bad_request("invalid JSON request body", None)
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

/// Read-only discovery metadata for agent bootstrap.
#[derive(Serialize, ToSchema)]
struct DiscoverResponse {
    /// Stable API level string advertised by this server.
    #[schema(value_type = String, example = "v1")]
    api_version: &'static str,
    /// Payload formats this API can produce or consume.
    #[schema(value_type = Vec<String>, example = json!(["json", "yaml", "toon", "markdown", "plaintext"]))]
    formats: Vec<&'static str>,
    /// Effective authorization scopes available to the authenticated caller.
    #[schema(value_type = Vec<String>, example = json!(["core:discover", "vault:read", "search:read", "entity:read", "sync:connect"]))]
    scopes: Vec<&'static str>,
    /// Static agentskills.io pack for progressive-disclosure memory guidance.
    skill_pack: SkillPackDiscovery,
    /// Context ids the server has already bound for the caller.
    bound: BoundContext,
    /// Known persona entities available for caller selection.
    personas: Vec<DiscoveredEntity>,
    /// Known conversation entities available for caller selection.
    conversations: Vec<DiscoveredEntity>,
    /// Capabilities and modes advertised by this API.
    feature_flags: FeatureFlags,
    /// Entity counts keyed by numeric entity type.
    #[schema(example = json!({"1": 3, "2": 1}))]
    counts: BTreeMap<String, u64>,
    /// Predicate namespaces discovered from claim predicates.
    predicate_namespaces: Vec<String>,
    /// Most recent learned-at timestamp observed during discovery, when available.
    #[schema(example = 1782357635_u64)]
    last_activity: Option<u64>,
    /// Resolved runtime routing status for supported model roles.
    runtime: RuntimeStatus,
}

/// Static progressive-disclosure pack advertised to external agents.
#[derive(Serialize, ToSchema)]
struct SkillPackDiscovery {
    /// Skill name from the committed pack frontmatter.
    #[schema(example = "oneiron-http-memory-api")]
    name: &'static str,
    /// Server-relative endpoint that serves the committed pack.
    #[schema(example = "/api/skills/oneiron.skills.md")]
    endpoint: &'static str,
    /// Compatibility format for the static skill pack.
    #[schema(example = "agentskills.io")]
    pack_format: &'static str,
    /// MIME type agents should use when loading the pack.
    #[schema(example = "text/markdown")]
    mime_type: &'static str,
    /// When to load the static pack during agent bootstrap.
    #[schema(example = "GET /api/skills/oneiron.skills.md before choosing memory calls.")]
    when_to_load: &'static str,
    /// How agents should resolve the committed pack artifact.
    #[schema(example = "Resolve endpoint against the same Oneiron HTTP origin.")]
    how_to_load: &'static str,
    /// Boundary between static guidance and callable MCP tools.
    #[schema(example = "skills = how to think about memory; MCP tools = what to call")]
    layer_boundary: &'static str,
}

/// Caller context that has already been bound by the API.
#[derive(Serialize, ToSchema)]
struct BoundContext {
    /// Bound vault id when the server has one for the caller.
    #[schema(example = "vault-local")]
    vault: Option<String>,
    /// Bound persona entity id when selected.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    persona: Option<String>,
    /// Bound conversation entity id when selected.
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    conversation: Option<String>,
}

/// Compact entity reference returned by discovery.
#[derive(Serialize, ToSchema)]
struct DiscoveredEntity {
    /// Hex-encoded entity id.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: String,
    /// Numeric entity type byte.
    #[schema(example = 1)]
    entity_type: u8,
}

/// Capability flags advertised by the HTTP API.
#[derive(Serialize, ToSchema)]
struct FeatureFlags {
    /// Operation capabilities clients may rely on.
    #[schema(value_type = Vec<String>, example = json!(["core.discover", "search.vector", "search.text"]))]
    capabilities: Vec<&'static str>,
    /// Model or runtime effort modes advertised by the API.
    #[schema(value_type = Vec<String>, example = json!(["flash", "thinking", "pro", "ultra"]))]
    modes: Vec<&'static str>,
}

/// Rate-limit settings advertised by health and discovery surfaces.
#[derive(Serialize, ToSchema)]
struct RateLimitStatus {
    /// Whether HTTP API requests are currently rate-limited.
    #[schema(example = false)]
    api_enforced: bool,
    /// Whether websocket messages are currently rate-limited.
    #[schema(example = true)]
    websocket_enforced: bool,
    /// Maximum inbound websocket messages per second.
    #[schema(example = 64)]
    max_messages_per_sec: u32,
    /// Maximum sync windows that may be attached to one connection.
    #[schema(example = 8)]
    max_windows_per_connection: usize,
    /// Maximum accepted websocket frame size in bytes.
    #[schema(example = 1048576)]
    max_frame_size_bytes: usize,
    /// Maximum accepted sync update payload size in bytes.
    #[schema(example = 1048576)]
    max_update_payload_bytes: usize,
}

/// Vault bootstrap discovery for external agents with only the Phase-1 auth
/// secret. This is read-only aggregation over existing vault indexes and
/// server config; it does not mint identity, mutate auth, or persist state.
#[utoipa::path(
    get,
    path = "/api/core/discover",
    responses(
        (
            status = 200,
            description = "Read-only capability and vault discovery metadata for external agents.",
            body = DiscoverResponse,
            content_type = "application/json",
            example = json!({
                "api_version": "v1",
                "formats": ["json", "yaml", "toon", "markdown", "plaintext"],
                "scopes": ["core:discover", "vault:read", "search:read", "entity:read", "sync:connect"],
                "skill_pack": {
                    "name": "oneiron-http-memory-api",
                    "endpoint": "/api/skills/oneiron.skills.md",
                    "pack_format": "agentskills.io",
                    "mime_type": "text/markdown",
                    "when_to_load": "GET /api/skills/oneiron.skills.md from the same Oneiron HTTP origin before choosing memory search, read, context-pack, discovery, or recovery calls; use MCP tools as the callable layer.",
                    "how_to_load": "Resolve endpoint against the same origin used for /api/core/discover and send the configured x-oneiron-secret; do not resolve the pack against a local working directory.",
                    "layer_boundary": "skills = how to think about memory; MCP tools = what to call"
                },
                "bound": {
                    "vault": null,
                    "persona": null,
                    "conversation": null
                },
                "personas": [{
                    "id": "0123456789abcdef0123456789abcdef",
                    "entity_type": 1
                }],
                "conversations": [{
                    "id": "fedcba9876543210fedcba9876543210",
                    "entity_type": 2
                }],
                "feature_flags": {
                    "capabilities": ["core.discover", "skills_pack.fetch", "search.vector", "search.text"],
                    "modes": ["flash", "thinking", "pro", "ultra"]
                },
                "runtime": {
                    "mode": "local_free",
                    "oneironSpendMetered": false,
                    "routes": [{
                        "role": "orchestrator",
                        "mode": "local_free",
                        "providerKind": "local",
                        "model": "local-orchestrator-default",
                        "state": "available",
                        "reason": "ready",
                        "provenance": {
                            "roleDefault": "orchestrator",
                            "source": "mode_preset"
                        },
                        "oneironSpendMetered": false
                    }]
                },
                "counts": {
                    "1": 3,
                    "2": 1
                },
                "predicate_namespaces": ["oneiron", "user"],
                "last_activity": 1782357635_u64
            })
        ),
        (
            status = 401,
            description = "Missing or invalid `x-oneiron-secret` header.",
            body = ApiError,
            content_type = "application/json",
            example = json!({
                "code": "UNAUTHORIZED",
                "message": "unauthorized",
                "details": { "code": "UNAUTHORIZED" },
                "suggestions": ["set x-oneiron-secret to the configured shared secret"]
            })
        ),
        (
            status = 500,
            description = "Discovery scan failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
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
        skill_pack: skill_pack_discovery(),
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
        runtime: runtime_status_for_config(&server.config),
    })
}

fn runtime_status_for_config(config: &SyncServerConfig) -> RuntimeStatus {
    if config.runtime == crate::runtime::RuntimeConfig::default() {
        let runtime =
            crate::runtime::RuntimeConfig::for_mode(RuntimeMode::from(config.runtime_usage_mode()));
        RuntimeStatus::from_config(&runtime)
    } else {
        RuntimeStatus::from_config(&config.runtime)
    }
}

fn runtime_health_status_for_config(config: &SyncServerConfig) -> RuntimeHealthStatus {
    if config.runtime == crate::runtime::RuntimeConfig::default() {
        let runtime =
            crate::runtime::RuntimeConfig::for_mode(RuntimeMode::from(config.runtime_usage_mode()));
        RuntimeHealthStatus::from_config(&runtime)
    } else {
        RuntimeHealthStatus::from_config(&config.runtime)
    }
}

fn skill_pack_discovery() -> SkillPackDiscovery {
    SkillPackDiscovery {
        name: SKILL_PACK_NAME,
        endpoint: SKILL_PACK_ENDPOINT,
        pack_format: SKILL_PACK_FORMAT,
        mime_type: SKILL_PACK_MIME_TYPE,
        when_to_load: SKILL_PACK_LOAD_HINT,
        how_to_load: SKILL_PACK_RESOLUTION,
        layer_boundary: SKILL_PACK_LAYER_BOUNDARY,
    }
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

// ─── Companion v1 profile access ─────────────────────────────────────────────

/// Scope payload for companion AccessGrant control-plane records.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[schema(example = json!({
    "kind": "companion_profile",
    "person_ref": "11111111111111111111111111111111",
    "persona_ref": "22222222222222222222222222222222"
}))]
struct CompanionAccessGrantScopePayload {
    /// Scope discriminator. Currently only `companion_profile` is accepted.
    #[schema(example = "companion_profile")]
    kind: String,
    /// Person scope for the companion profile.
    #[schema(example = "11111111111111111111111111111111")]
    person_ref: String,
    /// Persona/profile entity receiving scoped access.
    #[schema(example = "22222222222222222222222222222222")]
    persona_ref: String,
}

/// Request body for creating a companion AccessGrant.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "principal_ref": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "scope": {
        "kind": "companion_profile",
        "person_ref": "11111111111111111111111111111111",
        "persona_ref": "22222222222222222222222222222222"
    },
    "created_at": 1700000000
}))]
struct CompanionCreateAccessGrantRequest {
    /// Optional grant entity id. Defaults to a new UUIDv7 entity id.
    #[schema(example = "33333333333333333333333333333333")]
    id: Option<String>,
    /// Principal receiving access.
    #[schema(example = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    principal_ref: String,
    /// Exact companion profile scope.
    scope: CompanionAccessGrantScopePayload,
    /// Creation timestamp in Unix seconds. Defaults to server time.
    #[schema(example = 1700000000)]
    created_at: Option<u64>,
}

/// Request body for revoking a companion AccessGrant.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[schema(example = json!({ "revoked_at": 1700000300 }))]
struct CompanionRevokeAccessGrantRequest {
    /// Revocation timestamp in Unix seconds. Defaults to server time.
    #[schema(example = 1700000300)]
    revoked_at: Option<u64>,
}

/// AccessGrant response body.
#[derive(Clone, Debug, Serialize, ToSchema)]
struct CompanionAccessGrantResponse {
    /// Grant entity id.
    #[schema(example = "33333333333333333333333333333333")]
    id: String,
    /// Principal receiving access.
    #[schema(example = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    principal_ref: String,
    /// Exact companion profile scope.
    scope: CompanionAccessGrantScopePayload,
    /// Granted capability.
    #[schema(example = "companion_profile.read")]
    capability: String,
    /// Grant status.
    #[schema(example = "active")]
    status: String,
    /// Creation timestamp in Unix seconds.
    #[schema(example = 1700000000)]
    created_at: u64,
    /// Revocation timestamp when status is `revoked`.
    #[schema(example = 1700000300)]
    revoked_at: Option<u64>,
}

/// Query parameters for companion profile reads.
#[derive(Clone, Debug, Deserialize, IntoParams)]
struct CompanionProfileQuery {
    /// Principal requesting profile access.
    #[param(example = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    principal_ref: String,
    /// Person scope for the companion profile.
    #[param(example = "11111111111111111111111111111111")]
    person_ref: String,
}

/// Access evidence returned with a companion profile response.
#[derive(Clone, Debug, Serialize, ToSchema)]
struct CompanionProfileAccess {
    /// Grant entity id that authorized the response.
    #[schema(example = "33333333333333333333333333333333")]
    grant_id: String,
    /// Principal authorized by the grant.
    #[schema(example = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    principal_ref: String,
    /// Exact scope authorized by the grant.
    scope: CompanionAccessGrantScopePayload,
}

/// Companion profile access response.
#[derive(Clone, Debug, Serialize, ToSchema)]
struct CompanionProfileResponse {
    /// Persona/profile entity id.
    #[schema(example = "22222222222222222222222222222222")]
    persona_ref: String,
    /// Person scope for this profile.
    #[schema(example = "11111111111111111111111111111111")]
    person_ref: String,
    /// Grant evidence for the access decision.
    access: CompanionProfileAccess,
    /// Profile payload placeholder for the v1 shell.
    #[schema(value_type = Object)]
    profile: Value,
}

/// Scope boundary for a companion register record.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[schema(example = json!({
    "kind": "personal",
    "person_ref": "11111111111111111111111111111111"
}))]
struct CompanionRegisterScopePayload {
    /// Scope discriminator: `neutral`, `personal`, or `shared_vault`.
    #[schema(example = "personal")]
    kind: String,
    /// Person scope for `personal` records.
    #[schema(example = "11111111111111111111111111111111")]
    person_ref: Option<String>,
    /// Shared-vault id for `shared_vault` records.
    #[schema(example = 7)]
    vault_id: Option<u64>,
}

/// Relationship subject reference for companion register records.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[schema(example = json!({
    "source_ref": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "target_ref": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}))]
struct CompanionRegisterRelationshipRefPayload {
    /// Source entity in the companion relationship.
    #[schema(example = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    source_ref: String,
    /// Target entity in the companion relationship.
    #[schema(example = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")]
    target_ref: String,
}

/// Persona or relationship subject for a companion register record.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[schema(example = json!({
    "kind": "persona",
    "persona_ref": "22222222222222222222222222222222"
}))]
struct CompanionRegisterSubjectPayload {
    /// Subject discriminator: `persona` or `relationship`.
    #[schema(example = "persona")]
    kind: String,
    /// Persona entity for `persona` records.
    #[schema(example = "22222222222222222222222222222222")]
    persona_ref: Option<String>,
    /// Source/target pair for `relationship` records.
    relationship_ref: Option<CompanionRegisterRelationshipRefPayload>,
}

/// Provenance stamp for a companion register record.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[schema(example = json!({
    "actor_ref": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "actor_class": 1,
    "source": "user_stated",
    "approval": "approved",
    "value": { "source": "settings" }
}))]
struct CompanionRegisterProvenancePayload {
    /// Actor entity responsible for the write.
    #[schema(example = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    actor_ref: String,
    /// Actor class: 0 human, 1 agent, 2 system.
    #[schema(example = 1)]
    actor_class: u8,
    /// Provenance source.
    #[schema(example = "user_stated")]
    source: String,
    /// Approval status for this write.
    #[schema(example = "approved")]
    approval: String,
    /// Opaque provenance payload.
    #[schema(value_type = Object)]
    value: Value,
}

/// Typed companion register record envelope.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[schema(example = json!({
    "kind": "persona",
    "scope": { "kind": "personal", "person_ref": "11111111111111111111111111111111" },
    "subject": { "kind": "persona", "persona_ref": "22222222222222222222222222222222" },
    "value": { "note": "private relationship tuning" },
    "provenance": {
        "actor_ref": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "actor_class": 1,
        "source": "user_stated",
        "approval": "approved",
        "value": { "source": "settings" }
    },
    "lifecycle": "active",
    "export": "local_only"
}))]
struct CompanionRegisterRecordPayload {
    /// Record discriminator: `persona` or `relationship`.
    #[schema(example = "persona")]
    kind: String,
    /// Visibility/privacy scope.
    scope: CompanionRegisterScopePayload,
    /// Persona or relationship subject.
    subject: CompanionRegisterSubjectPayload,
    /// Opaque companion tuning/private note payload.
    #[schema(value_type = Object)]
    value: Value,
    /// Provenance stamp for this record.
    provenance: CompanionRegisterProvenancePayload,
    /// Lifecycle status. Defaults to `active` on create/update when omitted.
    #[schema(example = "active")]
    lifecycle: Option<String>,
    /// Export classification: `local_only`, `portable`, or `shared_vault`.
    #[serde(rename = "export")]
    #[schema(example = "local_only")]
    export_classification: String,
}

/// Create companion register record request.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": "33333333333333333333333333333333",
    "learned_at": 1700000000,
    "record": {
        "kind": "persona",
        "scope": { "kind": "neutral" },
        "subject": { "kind": "persona", "persona_ref": "22222222222222222222222222222222" },
        "value": { "style": "warm" },
        "provenance": {
            "actor_ref": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "actor_class": 1,
            "source": "user_stated",
            "approval": "approved",
            "value": { "source": "settings" }
        },
        "export": "portable"
    }
}))]
struct CompanionRegisterCreateRecordRequest {
    /// Optional companion record entity id. Defaults to a new UUIDv7 entity id.
    #[schema(example = "33333333333333333333333333333333")]
    id: Option<String>,
    /// Write timestamp in Unix seconds. Defaults to server time.
    #[schema(example = 1700000000)]
    learned_at: Option<u64>,
    /// Typed companion record envelope.
    record: CompanionRegisterRecordPayload,
}

/// Update companion register record request.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "learned_at": 1700000300,
    "record": {
        "kind": "persona",
        "scope": { "kind": "personal", "person_ref": "11111111111111111111111111111111" },
        "subject": { "kind": "persona", "persona_ref": "22222222222222222222222222222222" },
        "value": { "note": "updated private tuning" },
        "provenance": {
            "actor_ref": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "actor_class": 1,
            "source": "user_stated",
            "approval": "approved",
            "value": { "source": "settings" }
        },
        "export": "local_only"
    }
}))]
struct CompanionRegisterUpdateRecordRequest {
    /// Write timestamp in Unix seconds. Defaults to server time.
    #[schema(example = 1700000300)]
    learned_at: Option<u64>,
    /// Replacement record envelope. Scope and subject must match the existing record.
    record: CompanionRegisterRecordPayload,
}

/// Retire companion register record request.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[schema(example = json!({ "retired_at": 1700000600 }))]
struct CompanionRegisterRetireRecordRequest {
    /// Retirement timestamp in Unix seconds. Defaults to server time.
    #[schema(example = 1700000600)]
    retired_at: Option<u64>,
}

/// Companion register response envelope.
#[derive(Clone, Debug, Serialize, ToSchema)]
struct CompanionRegisterRecordResponse {
    /// Companion register entity id.
    #[schema(example = "33333333333333333333333333333333")]
    id: String,
    /// Typed companion register record.
    record: CompanionRegisterRecordPayload,
}

/// Create a scoped companion AccessGrant.
#[utoipa::path(
    post,
    path = "/v1/companion/access-grants",
    request_body(content = CompanionCreateAccessGrantRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "AccessGrant created.", body = CompanionAccessGrantResponse, content_type = "application/json"),
        (status = 400, description = "Malformed grant request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Token lacks core:auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 409, description = "AccessGrant id already exists.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "AccessGrant write failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn create_companion_access_grant(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CompanionCreateAccessGrantRequest>, JsonRejection>,
) -> Result<Json<CompanionAccessGrantResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Auth)?;
    let req = json_payload(payload)?;
    let grant_id = parse_optional_entity_id(req.id.as_deref(), "id")?;
    let principal_ref = parse_entity_id_param(&req.principal_ref, "principal_ref")?;
    let (person_ref, persona_ref) = companion_scope_entity_refs(&req.scope)?;
    let created_at = req.created_at.unwrap_or_else(unix_seconds_now);
    let grant = oneiron::AccessGrant::companion_profile_read(
        principal_ref,
        person_ref,
        persona_ref,
        created_at,
    );

    server
        .vault
        .create_access_grant(&grant_id, &grant)
        .map_err(|error| {
        tracing::error!(error = %error, id = %grant_id.to_hex(), "companion access grant create failed");
            companion_create_error(error)
        })?;

    Ok(Json(companion_access_grant_response(&grant_id, &grant)))
}

/// Revoke a scoped companion AccessGrant.
#[utoipa::path(
    post,
    path = "/v1/companion/access-grants/{grant_id}/revoke",
    params(("grant_id" = String, Path, description = "AccessGrant entity id.")),
    request_body(content = CompanionRevokeAccessGrantRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "AccessGrant revoked.", body = CompanionAccessGrantResponse, content_type = "application/json"),
        (status = 400, description = "Malformed grant id or request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Token lacks core:auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "AccessGrant was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "AccessGrant revoke failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn revoke_companion_access_grant(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(grant_id): Path<String>,
    payload: Result<Json<CompanionRevokeAccessGrantRequest>, JsonRejection>,
) -> Result<Json<CompanionAccessGrantResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Auth)?;
    let grant_id = parse_entity_id_param(&grant_id, "grant_id")?;
    let req = json_payload(payload)?;
    let revoked_at = req.revoked_at.unwrap_or_else(unix_seconds_now);

    let grant = server
        .vault
        .revoke_access_grant(&grant_id, revoked_at)
        .map_err(|error| {
            tracing::error!(error = %error, id = %grant_id.to_hex(), "companion access grant revoke failed");
            companion_engine_error("companion access grant revoke failed", error)
        })?;

    Ok(Json(companion_access_grant_response(&grant_id, &grant)))
}

/// Read a companion profile when an active matching AccessGrant exists.
#[utoipa::path(
    get,
    path = "/v1/companion/profiles/{persona_ref}",
    params(
        ("persona_ref" = String, Path, description = "Persona/profile entity id."),
        CompanionProfileQuery
    ),
    responses(
        (status = 200, description = "Companion profile access authorized.", body = CompanionProfileResponse, content_type = "application/json"),
        (status = 400, description = "Malformed profile request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "No active AccessGrant authorizes this profile.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "AccessGrant lookup failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn get_companion_profile(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(persona_ref): Path<String>,
    query: Result<Query<CompanionProfileQuery>, QueryRejection>,
) -> Result<Json<CompanionProfileResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let params = query_params(query)?;
    let persona_ref = parse_entity_id_param(&persona_ref, "persona_ref")?;
    let principal_ref = parse_entity_id_param(&params.principal_ref, "principal_ref")?;
    let person_ref = parse_entity_id_param(&params.person_ref, "person_ref")?;

    let grant_id = server
        .vault
        .companion_profile_access_grant(&principal_ref, &person_ref, &persona_ref)
        .map_err(|error| {
            tracing::error!(
                error = %error,
                principal_ref = %principal_ref.to_hex(),
                person_ref = %person_ref.to_hex(),
                persona_ref = %persona_ref.to_hex(),
                "companion profile grant lookup failed"
            );
            companion_engine_error("companion profile grant lookup failed", error)
        })?
        .ok_or_else(companion_access_denied)?;

    let scope = companion_scope_response(&person_ref, &persona_ref);
    Ok(Json(CompanionProfileResponse {
        persona_ref: persona_ref.to_hex(),
        person_ref: person_ref.to_hex(),
        access: CompanionProfileAccess {
            grant_id: grant_id.to_hex(),
            principal_ref: principal_ref.to_hex(),
            scope,
        },
        profile: json!({}),
    }))
}

/// Create a typed companion register record.
#[utoipa::path(
    post,
    path = "/v1/companion/register/records",
    request_body(content = CompanionRegisterCreateRecordRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Companion register record created.", body = CompanionRegisterRecordResponse, content_type = "application/json"),
        (status = 400, description = "Malformed companion register request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Token lacks core:write.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 409, description = "Companion register id or key already exists.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Companion register write failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn create_companion_register_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CompanionRegisterCreateRecordRequest>, JsonRejection>,
) -> Result<Json<CompanionRegisterRecordResponse>, EnvelopedApiError> {
    auth.require(CoreScope::CompanionRegisterWrite)?;
    let req = json_payload(payload)?;
    let id = parse_optional_entity_id(req.id.as_deref(), "id")?;
    let learned_at = req.learned_at.unwrap_or_else(unix_seconds_now);
    let record = companion_register_record_from_payload(&req.record)?;

    server
        .vault
        .create_companion_record(&id, &record, learned_at)
        .map_err(|error| {
            tracing::error!(error = %error, id = %id.to_hex(), "companion register create failed");
            companion_register_engine_error("companion register create failed", error)
        })?;

    Ok(Json(companion_register_record_response(&id, &record)))
}

/// Read a typed companion register record.
#[utoipa::path(
    get,
    path = "/v1/companion/register/records/{record_id}",
    params(("record_id" = String, Path, description = "Companion register entity id.")),
    responses(
        (status = 200, description = "Companion register record read.", body = CompanionRegisterRecordResponse, content_type = "application/json"),
        (status = 400, description = "Malformed companion register id.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Companion register record was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Companion register read failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn get_companion_register_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(record_id): Path<String>,
) -> Result<Json<CompanionRegisterRecordResponse>, EnvelopedApiError> {
    auth.require(CoreScope::CompanionRegisterRead)?;
    let id = parse_entity_id_param(&record_id, "record_id")?;
    let record = server
        .vault
        .get_companion_record(&id)
        .map_err(|error| {
            tracing::error!(error = %error, id = %id.to_hex(), "companion register read failed");
            companion_register_engine_error("companion register read failed", error)
        })?
        .ok_or_else(|| ApiError::not_found("companion_record", None))?;

    Ok(Json(companion_register_record_response(&id, &record)))
}

/// Update a typed companion register record.
#[utoipa::path(
    post,
    path = "/v1/companion/register/records/{record_id}",
    params(("record_id" = String, Path, description = "Companion register entity id.")),
    request_body(content = CompanionRegisterUpdateRecordRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Companion register record updated.", body = CompanionRegisterRecordResponse, content_type = "application/json"),
        (status = 400, description = "Malformed companion register request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Token lacks core:write.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Companion register record was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Companion register update failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn update_companion_register_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(record_id): Path<String>,
    payload: Result<Json<CompanionRegisterUpdateRecordRequest>, JsonRejection>,
) -> Result<Json<CompanionRegisterRecordResponse>, EnvelopedApiError> {
    auth.require(CoreScope::CompanionRegisterWrite)?;
    let id = parse_entity_id_param(&record_id, "record_id")?;
    let req = json_payload(payload)?;
    let learned_at = req.learned_at.unwrap_or_else(unix_seconds_now);
    let record = companion_register_record_from_payload(&req.record)?;

    let updated = server
        .vault
        .update_companion_record(&id, &record, learned_at)
        .map_err(|error| {
            tracing::error!(error = %error, id = %id.to_hex(), "companion register update failed");
            companion_register_engine_error("companion register update failed", error)
        })?;

    Ok(Json(companion_register_record_response(&id, &updated)))
}

/// Retire a typed companion register record.
#[utoipa::path(
    post,
    path = "/v1/companion/register/records/{record_id}/retire",
    params(("record_id" = String, Path, description = "Companion register entity id.")),
    request_body(content = CompanionRegisterRetireRecordRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Companion register record retired.", body = CompanionRegisterRecordResponse, content_type = "application/json"),
        (status = 400, description = "Malformed companion register id or request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Token lacks core:write.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Companion register record was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Companion register retire failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn retire_companion_register_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(record_id): Path<String>,
    payload: Result<Json<CompanionRegisterRetireRecordRequest>, JsonRejection>,
) -> Result<Json<CompanionRegisterRecordResponse>, EnvelopedApiError> {
    auth.require(CoreScope::CompanionRegisterWrite)?;
    let id = parse_entity_id_param(&record_id, "record_id")?;
    let req = json_payload(payload)?;
    let retired_at = req.retired_at.unwrap_or_else(unix_seconds_now);

    let retired = server
        .vault
        .retire_companion_record(&id, retired_at)
        .map_err(|error| {
            tracing::error!(error = %error, id = %id.to_hex(), "companion register retire failed");
            companion_register_engine_error("companion register retire failed", error)
        })?;

    Ok(Json(companion_register_record_response(&id, &retired)))
}

fn companion_scope_entity_refs(
    scope: &CompanionAccessGrantScopePayload,
) -> Result<(oneiron::EntityId, oneiron::EntityId), ApiError> {
    if scope.kind != "companion_profile" {
        return Err(ApiError::bad_request(
            "scope.kind must be companion_profile",
            Some("scope.kind"),
        ));
    }
    let person_ref = parse_entity_id_param(&scope.person_ref, "scope.person_ref")?;
    let persona_ref = parse_entity_id_param(&scope.persona_ref, "scope.persona_ref")?;
    Ok((person_ref, persona_ref))
}

fn companion_access_grant_response(
    id: &oneiron::EntityId,
    grant: &oneiron::AccessGrant,
) -> CompanionAccessGrantResponse {
    let (person_ref, persona_ref) = grant
        .scope
        .companion_profile_refs()
        .expect("companion access grants only expose companion_profile scopes");
    CompanionAccessGrantResponse {
        id: id.to_hex(),
        principal_ref: grant.principal_ref.to_hex(),
        scope: companion_scope_response(&person_ref, &persona_ref),
        capability: grant.capability.as_str().to_owned(),
        status: grant.status.as_str().to_owned(),
        created_at: grant.created_at,
        revoked_at: grant.revoked_at,
    }
}

fn companion_scope_response(
    person_ref: &oneiron::EntityId,
    persona_ref: &oneiron::EntityId,
) -> CompanionAccessGrantScopePayload {
    CompanionAccessGrantScopePayload {
        kind: "companion_profile".to_owned(),
        person_ref: person_ref.to_hex(),
        persona_ref: persona_ref.to_hex(),
    }
}

fn companion_register_record_from_payload(
    payload: &CompanionRegisterRecordPayload,
) -> Result<oneiron::CompanionRecord, ApiError> {
    let scope = companion_register_scope_from_payload(&payload.scope)?;
    let subject = companion_register_subject_from_payload(&payload.subject)?;
    let kind = companion_register_kind_from_wire(&payload.kind, "record.kind")?;
    if kind != subject.kind() {
        return Err(ApiError::bad_request(
            "record.kind must match subject.kind",
            Some("record.kind"),
        ));
    }
    companion_register_require_object_value(&payload.value, "record.value")?;
    let value = oneiron::companion_value_from_json(&payload.value)
        .map_err(|error| ApiError::bad_request(error.to_string(), Some("record.value")))?;
    let provenance = companion_register_provenance_from_payload(&payload.provenance)?;
    let lifecycle = payload
        .lifecycle
        .as_deref()
        .map(companion_register_lifecycle_from_wire)
        .transpose()?
        .unwrap_or(oneiron::ClaimLifecycleStatus::Active);
    let export_classification =
        companion_register_export_from_wire(&payload.export_classification)?;

    Ok(oneiron::CompanionRecord::new(
        scope,
        subject,
        value,
        provenance,
        lifecycle,
        export_classification,
    ))
}

fn companion_register_scope_from_payload(
    payload: &CompanionRegisterScopePayload,
) -> Result<oneiron::CompanionScope, ApiError> {
    match payload.kind.as_str() {
        "neutral" if payload.person_ref.is_none() && payload.vault_id.is_none() => {
            Ok(oneiron::CompanionScope::neutral())
        }
        "personal" if payload.vault_id.is_none() => {
            let Some(person_ref) = payload.person_ref.as_deref() else {
                return Err(ApiError::bad_request(
                    "personal scope requires person_ref",
                    Some("record.scope.person_ref"),
                ));
            };
            Ok(oneiron::CompanionScope::personal(parse_entity_id_param(
                person_ref,
                "record.scope.person_ref",
            )?))
        }
        "shared_vault" if payload.person_ref.is_none() => {
            let Some(vault_id) = payload.vault_id else {
                return Err(ApiError::bad_request(
                    "shared_vault scope requires vault_id",
                    Some("record.scope.vault_id"),
                ));
            };
            if vault_id == 0 {
                return Err(ApiError::bad_request(
                    "shared_vault scope requires nonzero vault_id",
                    Some("record.scope.vault_id"),
                ));
            }
            Ok(oneiron::CompanionScope::shared_vault(vault_id))
        }
        _ => Err(ApiError::bad_request(
            "scope shape must match scope.kind",
            Some("record.scope.kind"),
        )),
    }
}

fn companion_register_subject_from_payload(
    payload: &CompanionRegisterSubjectPayload,
) -> Result<oneiron::CompanionSubject, ApiError> {
    match payload.kind.as_str() {
        "persona" if payload.relationship_ref.is_none() => {
            let Some(persona_ref) = payload.persona_ref.as_deref() else {
                return Err(ApiError::bad_request(
                    "persona subject requires persona_ref",
                    Some("record.subject.persona_ref"),
                ));
            };
            Ok(oneiron::CompanionSubject::persona(parse_entity_id_param(
                persona_ref,
                "record.subject.persona_ref",
            )?))
        }
        "relationship" if payload.persona_ref.is_none() => {
            let Some(relationship_ref) = payload.relationship_ref.as_ref() else {
                return Err(ApiError::bad_request(
                    "relationship subject requires relationship_ref",
                    Some("record.subject.relationship_ref"),
                ));
            };
            Ok(oneiron::CompanionSubject::relationship(
                parse_entity_id_param(
                    &relationship_ref.source_ref,
                    "record.subject.relationship_ref.source_ref",
                )?,
                parse_entity_id_param(
                    &relationship_ref.target_ref,
                    "record.subject.relationship_ref.target_ref",
                )?,
            ))
        }
        _ => Err(ApiError::bad_request(
            "subject shape must match subject.kind",
            Some("record.subject.kind"),
        )),
    }
}

fn companion_register_provenance_from_payload(
    payload: &CompanionRegisterProvenancePayload,
) -> Result<oneiron::CompanionProvenance, ApiError> {
    companion_register_require_object_value(&payload.value, "record.provenance.value")?;
    let value = oneiron::companion_value_from_json(&payload.value).map_err(|error| {
        ApiError::bad_request(error.to_string(), Some("record.provenance.value"))
    })?;
    Ok(oneiron::CompanionProvenance::new(
        parse_entity_id_param(&payload.actor_ref, "record.provenance.actor_ref")?,
        companion_register_actor_class(payload.actor_class)?,
        companion_register_source_from_wire(&payload.source)?,
        companion_register_approval_from_wire(&payload.approval)?,
        value,
    ))
}

fn companion_register_require_object_value(
    value: &Value,
    field: &'static str,
) -> Result<(), ApiError> {
    if value.is_object() {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "companion register value must be a JSON object",
            Some(field),
        ))
    }
}

fn companion_register_record_response(
    id: &oneiron::EntityId,
    record: &oneiron::CompanionRecord,
) -> CompanionRegisterRecordResponse {
    CompanionRegisterRecordResponse {
        id: id.to_hex(),
        record: companion_register_record_payload(record),
    }
}

fn companion_register_record_payload(
    record: &oneiron::CompanionRecord,
) -> CompanionRegisterRecordPayload {
    CompanionRegisterRecordPayload {
        kind: record.kind().as_str().to_owned(),
        scope: companion_register_scope_payload(&record.scope),
        subject: companion_register_subject_payload(&record.subject),
        value: oneiron::companion_value_to_json(&record.value),
        provenance: CompanionRegisterProvenancePayload {
            actor_ref: record.provenance.actor_ref.to_hex(),
            actor_class: record.provenance.actor_class as u8,
            source: record.provenance.source.as_str().to_owned(),
            approval: record.provenance.approval.as_str().to_owned(),
            value: oneiron::companion_value_to_json(&record.provenance.value),
        },
        lifecycle: Some(record.lifecycle.as_str().to_owned()),
        export_classification: record.export_classification.as_str().to_owned(),
    }
}

fn companion_register_scope_payload(
    scope: &oneiron::CompanionScope,
) -> CompanionRegisterScopePayload {
    match scope {
        oneiron::CompanionScope::Neutral => CompanionRegisterScopePayload {
            kind: "neutral".to_owned(),
            person_ref: None,
            vault_id: None,
        },
        oneiron::CompanionScope::Personal { person_ref } => CompanionRegisterScopePayload {
            kind: "personal".to_owned(),
            person_ref: Some(person_ref.to_hex()),
            vault_id: None,
        },
        oneiron::CompanionScope::SharedVault { vault_id } => CompanionRegisterScopePayload {
            kind: "shared_vault".to_owned(),
            person_ref: None,
            vault_id: Some(*vault_id),
        },
        _ => unreachable!("unknown companion register scope variant"),
    }
}

fn companion_register_subject_payload(
    subject: &oneiron::CompanionSubject,
) -> CompanionRegisterSubjectPayload {
    match subject {
        oneiron::CompanionSubject::Persona { persona_ref } => CompanionRegisterSubjectPayload {
            kind: "persona".to_owned(),
            persona_ref: Some(persona_ref.to_hex()),
            relationship_ref: None,
        },
        oneiron::CompanionSubject::Relationship {
            source_ref,
            target_ref,
        } => CompanionRegisterSubjectPayload {
            kind: "relationship".to_owned(),
            persona_ref: None,
            relationship_ref: Some(CompanionRegisterRelationshipRefPayload {
                source_ref: source_ref.to_hex(),
                target_ref: target_ref.to_hex(),
            }),
        },
        _ => unreachable!("unknown companion register subject variant"),
    }
}

fn companion_register_kind_from_wire(
    value: &str,
    field: &'static str,
) -> Result<oneiron::CompanionRecordKind, ApiError> {
    match value {
        "persona" => Ok(oneiron::CompanionRecordKind::Persona),
        "relationship" => Ok(oneiron::CompanionRecordKind::Relationship),
        _ => Err(ApiError::bad_request(
            "kind must be persona or relationship",
            Some(field),
        )),
    }
}

fn companion_register_lifecycle_from_wire(
    value: &str,
) -> Result<oneiron::ClaimLifecycleStatus, ApiError> {
    match value {
        "active" => Ok(oneiron::ClaimLifecycleStatus::Active),
        "superseded" => Ok(oneiron::ClaimLifecycleStatus::Superseded),
        "retracted" => Ok(oneiron::ClaimLifecycleStatus::Retracted),
        _ => Err(ApiError::bad_request(
            "lifecycle must be active, superseded, or retracted",
            Some("record.lifecycle"),
        )),
    }
}

fn companion_register_export_from_wire(
    value: &str,
) -> Result<oneiron::CompanionExportClassification, ApiError> {
    match value {
        "local_only" => Ok(oneiron::CompanionExportClassification::LocalOnly),
        "portable" => Ok(oneiron::CompanionExportClassification::Portable),
        "shared_vault" => Ok(oneiron::CompanionExportClassification::SharedVault),
        _ => Err(ApiError::bad_request(
            "export must be local_only, portable, or shared_vault",
            Some("record.export"),
        )),
    }
}

fn companion_register_actor_class(value: u8) -> Result<oneiron::EdgeActorClass, ApiError> {
    match value {
        0 => Ok(oneiron::EdgeActorClass::Human),
        1 => Ok(oneiron::EdgeActorClass::Agent),
        2 => Ok(oneiron::EdgeActorClass::System),
        _ => Err(ApiError::bad_request(
            "actor_class must be 0, 1, or 2",
            Some("record.provenance.actor_class"),
        )),
    }
}

fn companion_register_source_from_wire(value: &str) -> Result<oneiron::ClaimSource, ApiError> {
    match value {
        "user_stated" => Ok(oneiron::ClaimSource::UserStated),
        "observed" => Ok(oneiron::ClaimSource::Observed),
        "inferred" => Ok(oneiron::ClaimSource::Inferred),
        "imported" => Ok(oneiron::ClaimSource::Imported),
        "tool_output" => Ok(oneiron::ClaimSource::ToolOutput),
        "generated" => Ok(oneiron::ClaimSource::Generated),
        _ => Err(ApiError::bad_request(
            "source is not recognized",
            Some("record.provenance.source"),
        )),
    }
}

fn companion_register_approval_from_wire(
    value: &str,
) -> Result<oneiron::ClaimApprovalStatus, ApiError> {
    match value {
        "auto" => Ok(oneiron::ClaimApprovalStatus::Auto),
        "proposed" => Ok(oneiron::ClaimApprovalStatus::Proposed),
        "approved" => Ok(oneiron::ClaimApprovalStatus::Approved),
        "rejected" => Ok(oneiron::ClaimApprovalStatus::Rejected),
        _ => Err(ApiError::bad_request(
            "approval is not recognized",
            Some("record.provenance.approval"),
        )),
    }
}

fn companion_access_denied() -> EnvelopedApiError {
    ApiError::new(
        "companion profile access is not granted",
        ApiErrorDetails::Forbidden {
            required_scope: Some("companion_profile.read".to_owned()),
        },
        ["Create an active AccessGrant for this principal and profile before retrying."],
    )
    .into()
}

fn companion_create_error(error: oneiron::Error) -> EnvelopedApiError {
    match error.kind() {
        ErrorKind::AccessGrantAlreadyExists => {
            ApiError::invalid_state(Some("access_grant_exists")).into()
        }
        _ => companion_engine_error("companion access grant create failed", error),
    }
}

fn companion_register_engine_error(
    message: &'static str,
    error: oneiron::Error,
) -> EnvelopedApiError {
    match error.kind() {
        ErrorKind::CompanionRecordAlreadyExists => {
            ApiError::invalid_state(Some("companion_record_exists")).into()
        }
        ErrorKind::EntityNotFound => ApiError::not_found("companion_record", None).into(),
        ErrorKind::InvalidClaimBody
        | ErrorKind::InvalidEntityType
        | ErrorKind::InvalidTimeRange
        | ErrorKind::StructuralKindBandViolation
        | ErrorKind::StructuralKindCollision
        | ErrorKind::InvalidStructuralKindRegistration => {
            ApiError::bad_request(error.to_string(), None).into()
        }
        _ => ApiError::internal_server_error(message).into(),
    }
}

fn companion_engine_error(message: &'static str, error: oneiron::Error) -> EnvelopedApiError {
    match error.kind() {
        ErrorKind::InvalidKey
        | ErrorKind::InvalidAccessGrantBody
        | ErrorKind::InvalidEntityType
        | ErrorKind::InvalidTimeRange => ApiError::bad_request(error.to_string(), None).into(),
        ErrorKind::EntityNotFound => ApiError::not_found("access_grant", None).into(),
        _ => ApiError::internal_server_error(message).into(),
    }
}

// ─── Companion resume ────────────────────────────────────────────────────────

/// One-shot read-only companion hydration.
/// POST /api/companion/resume
async fn resume(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<ResumeBundle>, ApiError> {
    check_api_auth(&headers, &server.config)?;
    let caller = resume_caller(&headers);
    resume_bundle(&server, &caller).map(Json)
}

fn resume_bundle(server: &SyncServer, caller: &str) -> Result<ResumeBundle, ApiError> {
    Ok(ResumeBundle::new(
        resume_session_context(server)?,
        pending_notifications(server, caller)?,
        pending_unprocessed_items(server, caller),
        current_resume_budget(server),
    ))
}

fn resume_session_context(server: &SyncServer) -> Result<SessionContext, ApiError> {
    let mut counts = BTreeMap::new();

    for entity_type in u8::MIN..=u8::MAX {
        let count = server
            .vault
            .count_entities_by_type(entity_type)
            .inspect_err(|e| {
                tracing::error!(error = %e, entity_type, "resume session count scan failed");
            })
            .map_err(|_| ApiError::internal_server_error("resume session count scan failed"))?;

        if count == 0 {
            continue;
        }

        counts.insert(entity_type.to_string(), count);
    }

    let last_activity = server
        .vault
        .latest_learned_at()
        .inspect_err(|e| {
            tracing::error!(error = %e, "resume activity summary failed");
        })
        .map_err(|_| ApiError::internal_server_error("resume activity summary failed"))?;

    Ok(SessionContext {
        api_version: API_LEVEL.to_owned(),
        counts,
        last_activity,
    })
}

fn pending_notifications(
    server: &SyncServer,
    caller: &str,
) -> Result<Vec<NotificationItem>, ApiError> {
    let mut notifications = Vec::new();

    let rows = server
        .vault
        .latest_entity_bodies_by_type(
            ENTITY_TYPE_NOTIFICATION,
            RESUME_NOTIFICATION_LIMIT,
            RESUME_NOTIFICATION_SCAN_LIMIT,
        )
        .inspect_err(|e| {
            tracing::error!(error = %e, "resume notification latest scan failed");
        })
        .map_err(|_| ApiError::internal_server_error("resume notification scan failed"))?;

    for (id, learned_at, raw_body) in rows {
        let Some(body) = notification_body_json(&raw_body) else {
            continue;
        };
        if !notification_scoped_to_caller(&body, caller) {
            continue;
        }
        if notification_already_surfaced(&body, caller) {
            continue;
        }
        notifications.push(NotificationItem {
            id: id.to_hex(),
            learned_at,
            body,
        });
    }

    Ok(notifications)
}

fn pending_unprocessed_items(_server: &SyncServer, _caller: &str) -> Vec<UnprocessedItem> {
    Vec::new()
}

fn current_resume_budget(_server: &SyncServer) -> ResumeBudget {
    ResumeBudget::from_meter(0, 0)
}

fn resume_caller(headers: &HeaderMap) -> String {
    headers
        .get("x-oneiron-caller")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .unwrap_or("default")
        .to_owned()
}

fn notification_body_json(raw_body: &[u8]) -> Option<Value> {
    let body: Value = rmp_serde::from_slice(raw_body).ok()?;
    body.as_object()?;
    Some(body)
}

fn notification_scoped_to_caller(body: &Value, caller: &str) -> bool {
    let Some(object) = body.as_object() else {
        return false;
    };

    const SCOPE_KEYS: &[&str] = &[
        "caller",
        "caller_id",
        "callerId",
        "recipient",
        "recipient_id",
        "recipientId",
    ];
    for key in SCOPE_KEYS {
        if let Some(value) = object.get(*key)
            && !caller_marker_contains(Some(value), caller)
        {
            return false;
        }
    }
    true
}

fn notification_already_surfaced(body: &Value, caller: &str) -> bool {
    let Some(object) = body.as_object() else {
        return false;
    };

    const GLOBAL_KEYS: &[&str] = &["acked", "acknowledged", "surfaced", "seen"];
    if GLOBAL_KEYS
        .iter()
        .any(|key| object.get(*key).and_then(Value::as_bool) == Some(true))
    {
        return true;
    }

    const CALLER_KEYS: &[&str] = &[
        "acked_by",
        "ackedBy",
        "acknowledged_by",
        "acknowledgedBy",
        "surfaced_by",
        "surfacedBy",
        "seen_by",
        "seenBy",
    ];
    CALLER_KEYS
        .iter()
        .any(|key| caller_marker_contains(object.get(*key), caller))
}

fn caller_marker_contains(value: Option<&Value>, caller: &str) -> bool {
    match value {
        Some(Value::Array(items)) => items.iter().any(|item| item.as_str() == Some(caller)),
        Some(Value::Object(map)) => map.get(caller).and_then(Value::as_bool) == Some(true),
        Some(Value::String(item)) => item == caller,
        _ => false,
    }
}

// ─── Usage Ledger ────────────────────────────────────────────────────────────

/// Query parameters for consumer usage reads.
#[derive(Deserialize, ToSchema, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
struct ConsumerUsageQuery {
    /// Tenant id whose usage and allowance should be read.
    #[schema(example = "tenant-a")]
    #[param(example = "tenant-a")]
    tenant_id: String,
    /// Optional vault id for a per-vault usage scope.
    #[schema(example = "vault-a")]
    #[param(example = "vault-a")]
    vault_id: Option<String>,
}

/// Optional selector for a tenant usage rollup.
#[derive(Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
struct UsageRollupQuery {
    /// Vault id to read a per-vault rollup. Omit for the tenant-wide rollup.
    #[schema(example = "vault-a")]
    #[param(example = "vault-a")]
    vault_id: Option<String>,
}

/// Reads consumer usage, allowance balance, and explicit warning state.
#[utoipa::path(
    get,
    path = "/v1/consumer/usage",
    params(ConsumerUsageQuery),
    responses(
        (
            status = 200,
            description = "Consumer usage and allowance state for the selected tenant or tenant/vault scope.",
            body = ConsumerUsageState,
            content_type = "application/json"
        ),
        (
            status = 400,
            description = "Invalid tenant or vault identifier.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid `x-oneiron-secret` header.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Consumer usage read failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
async fn get_consumer_usage(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<ConsumerUsageQuery>, QueryRejection>,
) -> Result<Json<ConsumerUsageState>, ApiError> {
    check_api_auth(&headers, &server.config)?;
    let params = query_params(query)?;
    let usage = server
        .usage_ledger
        .consumer_usage(
            &params.tenant_id,
            params.vault_id.as_deref(),
            server.config.usage_mode,
        )
        .inspect_err(|error| tracing::error!(error = %error, "consumer usage read failed"))
        .map_err(usage_error)?;
    Ok(Json(usage))
}

/// Reads consumer usage details including agent, model, and service breakdowns.
#[utoipa::path(
    get,
    path = "/v1/consumer/usage/details",
    params(ConsumerUsageQuery),
    responses(
        (
            status = 200,
            description = "Detailed consumer usage and allowance state for the selected tenant or tenant/vault scope.",
            body = ConsumerUsageDetails,
            content_type = "application/json"
        ),
        (
            status = 400,
            description = "Invalid tenant or vault identifier.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid `x-oneiron-secret` header.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Consumer usage details read failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
async fn get_consumer_usage_details(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<ConsumerUsageQuery>, QueryRejection>,
) -> Result<Json<ConsumerUsageDetails>, ApiError> {
    check_api_auth(&headers, &server.config)?;
    let params = query_params(query)?;
    let details = server
        .usage_ledger
        .consumer_usage_details(
            &params.tenant_id,
            params.vault_id.as_deref(),
            server.config.usage_mode,
        )
        .inspect_err(|error| tracing::error!(error = %error, "consumer usage details read failed"))
        .map_err(usage_error)?;
    Ok(Json(details))
}

/// Credits a tenant allowance without integrating a payment processor.
#[utoipa::path(
    post,
    path = "/v1/consumer/top-up",
    request_body(
        content = ConsumerTopUpRequest,
        content_type = "application/json",
        example = json!({
            "tenantId": "tenant-a",
            "idempotencyKey": "top-up-2026-06-29-0001",
            "creditUnits": 100.0
        })
    ),
    responses(
        (
            status = 200,
            description = "Top-up accepted or replayed by idempotency key.",
            body = ConsumerTopUpState,
            content_type = "application/json"
        ),
        (
            status = 400,
            description = "Invalid top-up payload.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 409,
            description = "Idempotency key was replayed with a different top-up payload.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid `x-oneiron-secret` header.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Top-up persistence failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
async fn top_up_consumer(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    request: Result<Json<ConsumerTopUpRequest>, JsonRejection>,
) -> Result<Json<ConsumerTopUpState>, ApiError> {
    check_api_auth(&headers, &server.config)?;
    let request = json_payload(request)?;
    let state = server
        .usage_ledger
        .top_up(request, server.config.usage_mode)
        .map_err(|error| {
            if matches!(error, UsageError::IdempotencyConflict { .. }) {
                tracing::warn!("consumer top-up idempotency conflict");
            } else {
                tracing::error!(error = %error, "consumer top-up failed");
            }
            usage_error(error)
        })?;
    Ok(Json(state))
}

/// Records one tenant usage event and returns the resulting debit decision.
#[utoipa::path(
    post,
    path = "/v1/usage/events",
    request_body(
        content = UsageEvent,
        content_type = "application/json",
        example = json!({
            "tenantId": "tenant-a",
            "vaultId": "vault-a",
            "idempotencyKey": "usage-2026-06-29T00:00:00Z-0001",
            "source": "oneiron_cloud",
            "eventType": "inference",
            "agentId": "agent-a",
            "model": "model-a",
            "service": "inference",
            "tokenCounts": {
                "inputTokens": 1000,
                "outputTokens": 500,
                "cacheReadTokens": 2000,
                "cacheWriteTokens": 1000
            },
            "costRates": {
                "inputTokenUsdPerMillion": 2.0,
                "outputTokenUsdPerMillion": 4.0,
                "cacheReadTokenUsdPerMillion": 0.5,
                "cacheWriteTokenUsdPerMillion": 1.0
            },
            "serviceCostUsd": 0.044
        })
    ),
    responses(
        (
            status = 200,
            description = "Usage event accepted. Local and BYO sources return no debit; Oneiron Cloud mode records each idempotency key once.",
            body = UsageRecordResult,
            content_type = "application/json"
        ),
        (
            status = 400,
            description = "Invalid usage payload.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid `x-oneiron-secret` header.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Usage ledger persistence failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
async fn record_usage_event(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Json(event): Json<UsageEvent>,
) -> Result<Json<UsageRecordResult>, ApiError> {
    check_api_auth(&headers, &server.config)?;
    let usage_mode = usage_mode_for_event(&server.config, &event)?;
    let result = server
        .usage_ledger
        .record_event(event, usage_mode)
        .inspect_err(|error| tracing::error!(error = %error, "usage event record failed"))
        .map_err(usage_error)?;
    Ok(Json(result))
}

fn usage_mode_for_event(
    config: &SyncServerConfig,
    event: &UsageEvent,
) -> Result<UsageMode, ApiError> {
    if config.runtime == crate::runtime::RuntimeConfig::default() {
        return Ok(config.runtime_usage_mode());
    }

    if let Some(usage_mode) = config.runtime.usage_mode_for_model(event.model.as_deref()) {
        return Ok(usage_mode);
    }
    if config.runtime.has_model_route_match(event.model.as_deref()) {
        return Err(ApiError::bad_request(
            "usage event model must match an available runtime route with a single debit boundary",
            Some("model"),
        ));
    }

    if let Some(usage_mode) = config.runtime.usage_mode_without_model() {
        return Ok(usage_mode);
    }

    Err(ApiError::bad_request(
        "usage event model is required when runtime routes mix metered and unmetered modes",
        Some("model"),
    ))
}

/// Reads a tenant-wide or tenant/vault-specific usage rollup.
#[utoipa::path(
    get,
    path = "/v1/usage/tenants/{tenant_id}/rollup",
    params(
        (
            "tenant_id" = String,
            Path,
            description = "Tenant id whose usage rollup should be read.",
            example = "tenant-a"
        ),
        UsageRollupQuery
    ),
    responses(
        (
            status = 200,
            description = "Tenant or vault usage rollup.",
            body = UsageRollup,
            content_type = "application/json"
        ),
        (
            status = 400,
            description = "Invalid tenant or vault identifier.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid `x-oneiron-secret` header.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 404,
            description = "No usage rollup exists for the selected tenant or vault.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Usage rollup read failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
async fn get_usage_rollup(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Path(tenant_id): Path<String>,
    query: Result<Query<UsageRollupQuery>, QueryRejection>,
) -> Result<Json<UsageRollup>, ApiError> {
    check_api_auth(&headers, &server.config)?;
    let params = query_params(query)?;
    let rollup = if let Some(vault_id) = params.vault_id {
        server
            .usage_ledger
            .vault_rollup(&tenant_id, &vault_id)
            .inspect_err(|error| tracing::error!(error = %error, "usage vault rollup read failed"))
            .map_err(usage_error)?
    } else {
        server
            .usage_ledger
            .tenant_rollup(&tenant_id)
            .inspect_err(|error| tracing::error!(error = %error, "usage tenant rollup read failed"))
            .map_err(usage_error)?
    };

    rollup
        .map(Json)
        .ok_or_else(|| ApiError::not_found("usage rollup", Some(&tenant_id)))
}

fn usage_error(error: UsageError) -> ApiError {
    if let UsageError::IdempotencyConflict {
        idempotency_key, ..
    } = &error
    {
        return consumer_top_up_idempotency_conflict_error(idempotency_key);
    }

    if let Some(field) = error.field() {
        return ApiError::bad_request(error.to_string(), Some(field));
    }

    ApiError::internal_server_error("usage ledger persistence failed")
}

fn consumer_top_up_idempotency_conflict_error(idempotency_key: &str) -> ApiError {
    ApiError::new(
        "idempotency key was replayed with a different request",
        ApiErrorDetails::IdempotencyReplayConflict {
            idempotency_key: Some(idempotency_key.to_owned()),
        },
        ["Reuse the original top-up request body or send a new JSON idempotencyKey."],
    )
}

// ─── Search Routes ────────────────────────────────────────────────────────────

/// Query parameters for vector similarity search.
#[derive(Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
#[schema(example = json!({
    "query": "0.12,-0.04,0.98",
    "limit": 10,
    "countMode": "estimate"
}))]
struct VectorSearchQuery {
    /// Comma-separated `f32` embedding values used as the vector search probe.
    #[schema(example = "0.12,-0.04,0.98")]
    #[param(example = "0.12,-0.04,0.98")]
    query: String,
    /// Maximum number of nearest entities to return. Defaults to `10` when omitted.
    #[serde(default = "default_limit")]
    #[schema(default = default_limit, example = 10)]
    #[param(default = 10, example = 10)]
    limit: usize,
    /// Optional projection view for returned items. Defaults to `summary`.
    #[schema(example = "summary")]
    #[param(example = "summary")]
    view: Option<View>,
    /// Count precision for response metadata. Search defaults to estimate.
    #[serde(default = "CountMode::default_estimate", rename = "countMode")]
    #[schema(example = "estimate")]
    #[param(example = "estimate")]
    count_mode: CountMode,
}

fn default_limit() -> usize {
    10
}

/// Search hit returned by vector and text search endpoints.
#[derive(Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": "0123456789abcdef0123456789abcdef",
    "score": 0.87
}))]
struct SearchResult {
    /// Hex-encoded entity id for the matched vault record.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: String,
    /// Ranking score from the selected retrieval engine; vector search reports the vector score or distance, while text search reports BM25 relevance. Compare scores only within one response.
    #[schema(example = 0.87)]
    score: f32,
}

type SearchResponse = PaginatedResponse<Value>;

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
            description = "Missing or invalid `x-oneiron-secret` header.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Vector search or projection failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
async fn search_vector(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<VectorSearchQuery>, QueryRejection>,
) -> Result<Json<SearchResponse>, ApiError> {
    check_api_auth(&headers, &server.config)?;
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

    let results = server
        .vault
        .search_vector(&query, fetch_limit)
        .inspect_err(|e| {
            tracing::error!(error = %e, "vector search failed");
        })
        .map_err(|_| ApiError::internal_server_error("vector search failed"))?;

    let total = results.len();
    let response = search_response(&server.vault, results, view, params.limit)?;
    let meta = search_meta(count_mode, total);

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
struct TextSearchQuery {
    /// Natural-language or keyword query used by the BM25 text index.
    #[schema(example = "project kickoff notes")]
    #[param(example = "project kickoff notes")]
    query: String,
    /// Maximum number of text hits to return. Defaults to `10` when omitted.
    #[serde(default = "default_limit")]
    #[schema(default = default_limit, example = 10)]
    #[param(default = 10, example = 10)]
    limit: usize,
    /// Optional projection view for returned items. Defaults to `summary`.
    #[schema(example = "summary")]
    #[param(example = "summary")]
    view: Option<View>,
    /// Count precision for response metadata. Search defaults to estimate.
    #[serde(default = "CountMode::default_estimate", rename = "countMode")]
    #[schema(example = "estimate")]
    #[param(example = "estimate")]
    count_mode: CountMode,
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
            description = "Missing or invalid `x-oneiron-secret` header.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Text search or projection failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
async fn search_text(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<TextSearchQuery>, QueryRejection>,
) -> Result<Json<SearchResponse>, ApiError> {
    check_api_auth(&headers, &server.config)?;
    let params = query_params(query)?;
    let view = params.view.unwrap_or(View::Summary);

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
    let response = search_response(&server.vault, results, view, params.limit)?;
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

fn search_response(
    vault: &oneiron::Vault,
    results: Vec<oneiron::ScoredEntity>,
    view: View,
    page_limit: usize,
) -> Result<Vec<Value>, ApiError> {
    let mut response = Vec::with_capacity(results.len().min(page_limit));
    for result in results {
        match projection::project_search_result(vault, result, view) {
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

// ─── Entity Routes ────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
struct ViewQuery {
    /// Optional projection view. Entity reads default to `standard`; edge reads default to `summary`.
    #[schema(example = "standard")]
    #[param(example = "standard")]
    view: Option<View>,
}

/// Get entity by ID.
#[utoipa::path(
    get,
    path = "/api/entity/{id}",
    params(
        (
            "id" = String,
            Path,
            description = "Hex-encoded entity id to retrieve from the vault. Agents should pass ids exactly as returned by search results.",
            example = "0123456789abcdef0123456789abcdef"
        ),
        ViewQuery
    ),
    responses(
        (
            status = 200,
            description = "Raw entity payload bytes for the requested id when `view=standard` or omitted. `view=summary` and `view=full` return JSON projections.",
            content(
                (
                    String = "application/octet-stream",
                    example = "raw entity bytes"
                ),
                (
                    Object = "application/json",
                    examples(
                        (
                            "summary" = (
                                summary = "Summary projection",
                                value = json!({
                                    "id": "0123456789abcdef0123456789abcdef",
                                    "kind": "TASK",
                                    "label": "Ship OpenAPI projections",
                                    "updatedAt": 1782357635_u64
                                })
                            )
                        ),
                        (
                            "full" = (
                                summary = "Full projection",
                                value = json!({
                                    "id": "0123456789abcdef0123456789abcdef",
                                    "kind": "TASK",
                                    "type": 1,
                                    "label": "Ship OpenAPI projections",
                                    "updatedAt": 1782357635_u64,
                                    "title": "Ship OpenAPI projections",
                                    "body": "Document JSON entity projection responses."
                                })
                            )
                        )
                    )
                )
            )
        ),
        (
            status = 400,
            description = "Malformed entity id or invalid view query parameter.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid `x-oneiron-secret` header.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 404,
            description = "No entity exists for the supplied id.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Entity lookup or projection failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
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
#[utoipa::path(
    get,
    path = "/api/edges/{id}",
    params(
        (
            "id" = String,
            Path,
            description = "Hex-encoded source entity id whose outbound edge list should be returned.",
            example = "0123456789abcdef0123456789abcdef"
        ),
        ViewQuery
    ),
    responses(
        (
            status = 200,
            description = "Outbound graph edges from the requested entity, projected according to `view`.",
            body = Vec<Object>,
            content_type = "application/json",
            example = json!([{
                "kind": 1,
                "target": "fedcba9876543210fedcba9876543210"
            }])
        ),
        (
            status = 400,
            description = "Malformed entity id or invalid view query parameter.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid `x-oneiron-secret` header.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Edge lookup failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
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

/// Outbound edge from one entity to another.
#[derive(Serialize, ToSchema)]
#[schema(example = json!({
    "kind": 1,
    "target": "fedcba9876543210fedcba9876543210",
    "weight": 1.0,
    "created_at": 1782357635_u64
}))]
struct EdgeResult {
    /// Numeric edge-kind discriminant used by the vault graph index.
    #[schema(example = 1)]
    kind: u8,
    /// Hex-encoded target entity id reached by this outbound edge.
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    target: String,
    /// Edge weight used by graph and context ranking.
    #[schema(example = 1.0)]
    weight: f32,
    /// Creation timestamp recorded for the edge, expressed as Unix seconds.
    #[schema(example = 1782357635_u64)]
    created_at: u64,
}

// ─── Core API parity routes ─────────────────────────────────────────────────

/// One text-index field to write alongside an entity body in a core batch.
#[derive(Debug, Deserialize, ToSchema)]
struct CoreTextField {
    /// Text index field name.
    #[schema(example = "body")]
    field: String,
    /// Text value to index for this field.
    #[schema(example = "blue hallway door")]
    value: String,
}

/// Entity put operation accepted by the canonical core batch route.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": "0123456789abcdef0123456789abcdef",
    "entity_type": 1,
    "occurred_start": 1782357600_u64,
    "occurred_end": 1782357600_u64,
    "learned_at": 1782357635_u64,
    "body": {
        "txt": "I saw a blue hallway door.",
        "spkr": "user",
        "at": 1782357600_u64
    },
    "text": [{ "field": "body", "value": "blue hallway door" }]
}))]
struct CoreBatchEntityInput {
    /// Optional hex entity id. When omitted, the server generates an id.
    #[serde(default)]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: Option<String>,
    /// Numeric entity type byte.
    #[serde(rename = "entity_type", alias = "entityType")]
    #[schema(example = 1)]
    entity_type: u8,
    /// Occurrence start timestamp in Unix seconds. Defaults to `learned_at` or current server time.
    #[serde(default, rename = "occurred_start", alias = "occurredStart")]
    #[schema(example = 1782357600_u64)]
    occurred_start: Option<u64>,
    /// Occurrence end timestamp in Unix seconds. Defaults to `occurred_start`.
    #[serde(default, rename = "occurred_end", alias = "occurredEnd")]
    #[schema(example = 1782357600_u64)]
    occurred_end: Option<u64>,
    /// Learned-at timestamp in Unix seconds. Defaults to current server time.
    #[serde(default, rename = "learned_at", alias = "learnedAt")]
    #[schema(example = 1782357635_u64)]
    learned_at: Option<u64>,
    /// JSON body encoded into the vault's msgpack entity payload.
    #[schema(value_type = Object, example = json!({"txt": "I saw a blue hallway door."}))]
    body: Value,
    /// Optional explicit text index fields. When omitted, top-level string body fields are indexed.
    #[serde(default)]
    text: Option<Vec<CoreTextField>>,
}

/// Core batch request envelope.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "entities": [{
        "entity_type": 1,
        "body": { "txt": "Blue hallway door", "spkr": "user", "at": 1782357600_u64 }
    }]
}))]
struct CoreBatchRequest {
    /// Entity put operations to commit atomically.
    entities: Vec<CoreBatchEntityInput>,
}

/// Entity write summary returned by core write routes.
#[derive(Debug, Serialize, ToSchema)]
struct CoreBatchEntityResult {
    /// Hex-encoded entity id written by the batch.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: String,
    /// Numeric entity type byte.
    #[schema(example = 1)]
    entity_type: u8,
}

/// Core batch response envelope.
#[derive(Debug, Serialize, ToSchema)]
struct CoreBatchResponse {
    /// Number of entity puts committed.
    #[schema(example = 1)]
    count: usize,
    /// Entity ids written by the batch.
    entities: Vec<CoreBatchEntityResult>,
}

/// Unified core query request over existing text/vector retrieval APIs.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "query": "blue hallway",
    "query_vector": [0.1, 0.2, 0.3, 0.4],
    "limit": 10,
    "view": "summary",
    "countMode": "estimate"
}))]
struct CoreQueryRequest {
    /// Optional BM25 text query.
    #[serde(default)]
    #[schema(example = "blue hallway")]
    query: Option<String>,
    /// Optional vector query. If supplied with `query`, the retrieval pipeline combines signals.
    #[serde(default, rename = "query_vector", alias = "queryVector")]
    #[schema(example = json!([0.1, 0.2, 0.3, 0.4]))]
    query_vector: Option<Vec<f32>>,
    /// Maximum result count.
    #[serde(default = "default_limit")]
    #[schema(default = default_limit, example = 10)]
    limit: usize,
    /// Projection view for returned entities. Defaults to summary.
    #[serde(default)]
    #[schema(example = "summary")]
    view: Option<View>,
    /// Count precision for response metadata. Query defaults to estimate.
    #[serde(
        default = "CountMode::default_estimate",
        rename = "countMode",
        alias = "count_mode"
    )]
    #[schema(example = "estimate")]
    count_mode: CountMode,
}

/// Short-id hydrate request.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "ref": "tn1:a7",
    "view": "full"
}))]
struct CoreHydrateRequest {
    /// Canonical short reference in `shortId:contentHashHex` form.
    #[serde(default, rename = "ref", alias = "short_ref", alias = "shortRef")]
    #[schema(example = "tn1:a7")]
    reference: Option<String>,
    /// Short id without the content hash, accepted when `content_hash` is also supplied.
    #[serde(default, rename = "short_id", alias = "shortId")]
    #[schema(example = "tn1")]
    short_id: Option<String>,
    /// Two-hex-digit content hash, accepted when `short_id` is also supplied.
    #[serde(default, rename = "content_hash", alias = "contentHash")]
    #[schema(example = "a7")]
    content_hash: Option<String>,
    /// Projection view for live entities. Defaults to full.
    #[serde(default)]
    #[schema(example = "full")]
    view: Option<View>,
}

/// Short-id hydrate status.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum CoreHydrateStatus {
    /// The short ref resolved to a live entity payload.
    Live,
    /// The short ref resolved to a deleted shell or dangling short-id row.
    Deleted,
}

/// Short-id hydrate response.
#[derive(Debug, Serialize, ToSchema)]
struct CoreHydrateResponse {
    /// Hydrate state for the resolved short ref.
    status: CoreHydrateStatus,
    /// Requested short id without content hash.
    #[serde(rename = "short_id")]
    #[schema(example = "tn1")]
    short_id: String,
    /// Requested content hash as two lowercase hex digits.
    #[serde(rename = "content_hash")]
    #[schema(example = "a7")]
    content_hash: String,
    /// Hex entity id when the short ref resolves.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: Option<String>,
    /// Numeric entity type byte when the entity header is still present.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 1)]
    entity_type: Option<u8>,
    /// Explicit deletion metadata for deleted refs.
    #[serde(skip_serializing_if = "Option::is_none")]
    deletion: Option<CoreHydrateDeletionMetadata>,
    /// Projected live entity. Omitted for deleted refs.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    item: Option<Value>,
}

/// Deletion metadata returned for a deleted short-id hydrate result.
#[derive(Debug, Serialize, ToSchema)]
struct CoreHydrateDeletionMetadata {
    /// Storage evidence that proved deletion.
    source: CoreHydrateDeletionSource,
    /// Decoded tombstone reason, absent for legacy/malformed/dangling rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<CoreHydrateDeletionReason>,
    /// Unix seconds from tombstone metadata when available.
    #[serde(skip_serializing_if = "Option::is_none", rename = "deleted_at")]
    #[schema(example = 1771027200_u64)]
    deleted_at: Option<u64>,
    /// Deletion request UUID when the v2 tombstone carried one.
    #[serde(skip_serializing_if = "Option::is_none", rename = "request_id")]
    #[schema(example = "00000000-0000-0000-0000-000000000000")]
    request_id: Option<String>,
    /// Whether the tombstone effect class is destructive/hard.
    hard: bool,
}

/// Source of deletion evidence for short-id hydrate.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum CoreHydrateDeletionSource {
    Tombstone,
    PendingTombstone,
    DanglingShortId,
}

/// Decoded short-id hydrate deletion reason.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum CoreHydrateDeletionReason {
    #[serde(rename = "user_delete")]
    User,
    #[serde(rename = "user_hard_delete")]
    UserHard,
    #[serde(rename = "gdpr_delete")]
    Gdpr,
    #[serde(rename = "policy_delete")]
    Policy,
}

/// Batch short-id hydrate request.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "refs": ["tn1:a7", "tn2:ff"],
    "view": "full"
}))]
struct CoreBatchShortIdHydrateRequest {
    /// Canonical short references in `shortId:contentHashHex` form.
    #[serde(
        default,
        rename = "refs",
        alias = "short_refs",
        alias = "shortRefs",
        alias = "short_ids",
        alias = "shortIds"
    )]
    #[schema(example = json!(["tn1:a7", "tn2:ff"]))]
    refs: Vec<String>,
    /// Projection view for live entities. Defaults to full.
    #[serde(default)]
    #[schema(example = "full")]
    view: Option<View>,
}

/// Batch short-id hydrate response.
#[derive(Debug, Serialize, ToSchema)]
struct CoreBatchShortIdHydrateResponse {
    /// Per-input hydrate result or typed error.
    results: Vec<CoreBatchShortIdHydrateItem>,
}

/// One batch short-id hydrate item.
#[derive(Debug, Serialize, ToSchema)]
struct CoreBatchShortIdHydrateItem {
    /// Input short ref.
    #[serde(rename = "ref")]
    #[schema(example = "tn1:a7")]
    reference: String,
    /// Stable per-input hydrate outcome discriminator.
    outcome: CoreShortIdHydrateOutcome,
    /// Live or deleted hydrate payload when the input resolves.
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<CoreHydrateResponse>,
    /// Typed per-input error for malformed or not-found refs.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<CoreShortIdHydrateError>,
}

/// Stable per-input short-id hydrate outcome.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum CoreShortIdHydrateOutcome {
    Live,
    Deleted,
    MalformedShortId,
    NotFound,
}

/// Per-input short-id hydrate error.
#[derive(Debug, Serialize, ToSchema)]
struct CoreShortIdHydrateError {
    /// Stable machine-readable per-item error kind.
    kind: CoreShortIdHydrateErrorKind,
    /// Human-readable error summary.
    message: String,
    /// Request field that failed validation, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,
}

/// Stable per-input short-id hydrate error kind.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum CoreShortIdHydrateErrorKind {
    MalformedShortId,
    NotFound,
}

/// Supersession timeline response for one memory anchor.
#[derive(Debug, Serialize, ToSchema)]
struct CoreMemoryTimelineResponse {
    /// Requested anchor entity id.
    #[serde(rename = "anchor_id")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    anchor_id: String,
    /// Stable ordered timeline records, oldest bitemporal start first.
    records: Vec<CoreMemoryTimelineRecord>,
}

/// One renderer-ready record in a supersession timeline.
#[derive(Debug, Serialize, ToSchema)]
struct CoreMemoryTimelineRecord {
    /// Hex entity id.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: String,
    /// Explicit lifecycle/deletion state for this timeline row.
    state: CoreMemoryTimelineRecordState,
    /// Numeric entity type byte when the record is still locally present.
    #[serde(skip_serializing_if = "Option::is_none", rename = "entity_type")]
    #[schema(example = 0)]
    entity_type: Option<u8>,
    /// Entity occurrence start timestamp.
    #[serde(skip_serializing_if = "Option::is_none", rename = "occurred_start")]
    #[schema(example = 1782357600_u64)]
    occurred_start: Option<u64>,
    /// Entity occurrence end timestamp.
    #[serde(skip_serializing_if = "Option::is_none", rename = "occurred_end")]
    #[schema(example = 1782357635_u64)]
    occurred_end: Option<u64>,
    /// Entity learned-at timestamp.
    #[serde(skip_serializing_if = "Option::is_none", rename = "learned_at")]
    #[schema(example = 1782357635_u64)]
    learned_at: Option<u64>,
    /// Stored body byte length for present records, including zero-byte live bodies.
    #[serde(skip_serializing_if = "Option::is_none", rename = "body_bytes")]
    #[schema(example = 48)]
    body_bytes: Option<usize>,
    /// Deletion metadata for deleted-shell rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    deletion: Option<CoreHydrateDeletionMetadata>,
    /// Older records this record supersedes.
    supersedes: Vec<String>,
    /// Newer records that supersede this record.
    #[serde(rename = "superseded_by")]
    superseded_by: Vec<String>,
    /// Projected entity payload for non-deleted present records.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    item: Option<Value>,
}

/// Stable row state in a memory timeline.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum CoreMemoryTimelineRecordState {
    Live,
    Superseded,
    Retracted,
    Deleted,
    Missing,
}

/// Payload for the named memory verb route.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "new_id": "22222222222222222222222222222222",
    "old_id": "11111111111111111111111111111111",
    "at": 1782357700_u64
}))]
struct CoreMemoryVerbRequest {
    /// Entity payload for the `remember` verb.
    #[serde(default)]
    entity: Option<CoreBatchEntityInput>,
    /// Target entity id for `retract`, `delete`, and `hard_delete`.
    #[serde(default)]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: Option<String>,
    /// New claim id for `supersede`.
    #[serde(default, rename = "new_id", alias = "newId")]
    #[schema(example = "22222222222222222222222222222222")]
    new_id: Option<String>,
    /// Old claim id for `supersede`.
    #[serde(default, rename = "old_id", alias = "oldId")]
    #[schema(example = "11111111111111111111111111111111")]
    old_id: Option<String>,
    /// Operation timestamp for supersede/retract verbs. Defaults to server time.
    /// Delete verbs reject this field because the vault owns deletion time.
    #[serde(default, alias = "now")]
    #[schema(example = 1782357700_u64)]
    at: Option<u64>,
    /// Delete reason override for delete verbs.
    #[serde(default)]
    reason: Option<CoreMemoryVerbDeleteReason>,
}

/// Named delete reason accepted by the memory verb route.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum CoreMemoryVerbDeleteReason {
    #[serde(rename = "user_delete")]
    User,
    #[serde(rename = "user_hard_delete")]
    UserHard,
    #[serde(rename = "gdpr_delete")]
    Gdpr,
    #[serde(rename = "policy_delete")]
    Policy,
}

/// Named memory verb response.
#[derive(Debug, Serialize, ToSchema)]
struct CoreMemoryVerbResponse {
    /// Canonical verb name selected after alias resolution.
    #[schema(example = "supersede")]
    verb: String,
    /// Typed operation family selected by the verb.
    operation: CoreMemoryOperationKind,
    /// Operation timestamp used by supersede/retract verbs.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 1782357700_u64)]
    at: Option<u64>,
    /// Target id for single-target verbs.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: Option<String>,
    /// New claim id for supersession.
    #[serde(skip_serializing_if = "Option::is_none", rename = "new_id")]
    #[schema(example = "22222222222222222222222222222222")]
    new_id: Option<String>,
    /// Old claim id for supersession.
    #[serde(skip_serializing_if = "Option::is_none", rename = "old_id")]
    #[schema(example = "11111111111111111111111111111111")]
    old_id: Option<String>,
    /// Entity written by `remember`.
    #[serde(skip_serializing_if = "Option::is_none")]
    entity: Option<CoreBatchEntityResult>,
    /// Delete outcome for delete verbs.
    #[serde(skip_serializing_if = "Option::is_none")]
    delete: Option<CoreMemoryVerbDeleteOutcome>,
}

/// Delete operation result returned by named delete verbs.
#[derive(Debug, Serialize, ToSchema)]
struct CoreMemoryVerbDeleteOutcome {
    /// Whether the delete found active local state to erase.
    existed: bool,
    /// Reason applied by the delete operation.
    reason: CoreMemoryVerbDeleteReason,
    /// Whether the reason has hard-delete semantics.
    hard: bool,
    /// Redaction receipt entity id for hard-delete classes.
    #[serde(skip_serializing_if = "Option::is_none", rename = "receipt_id")]
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    receipt_id: Option<String>,
    /// Hex-encoded hard-erasure sweep key when one was queued.
    #[serde(skip_serializing_if = "Option::is_none", rename = "sweep_key")]
    #[schema(example = "686172646572617365")]
    sweep_key: Option<String>,
}

/// Typed operation family selected by a named memory verb.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum CoreMemoryOperationKind {
    PutEntity,
    SupersedeClaim,
    RetractClaim,
    DeleteEntity,
}

/// Edge expansion depth controls for context-pack assembly.
#[derive(Debug, Default, Deserialize, ToSchema)]
struct ContextPackDepthControls {
    /// Edge expansion depth for neighbor hydration.
    #[serde(default, rename = "edge_hop", alias = "edgeHop")]
    #[schema(example = 1)]
    edge_hop: Option<u32>,
    /// Maximum neighbors to hydrate during edge expansion.
    #[serde(default, rename = "max_neighbors", alias = "maxNeighbors")]
    #[schema(example = 50)]
    max_neighbors: Option<usize>,
}

/// Ranking and projection policy controls for context-pack assembly.
#[derive(Debug, Default, Deserialize, ToSchema)]
struct ContextPackPolicyControls {
    /// Whether to include hydrated fields.
    #[serde(default)]
    #[schema(example = true)]
    hydrate: Option<bool>,
    /// Whether to include edge records in hydrated entities.
    #[serde(default, rename = "include_edges", alias = "includeEdges")]
    #[schema(example = true)]
    include_edges: Option<bool>,
    /// Whether to include stored vectors when present.
    #[serde(default, rename = "include_vectors", alias = "includeVectors")]
    #[schema(example = false)]
    include_vectors: Option<bool>,
    /// Field profile for hydrated fields.
    #[serde(default)]
    #[schema(example = "standard")]
    view: Option<View>,
    /// Apply recency boost with the supplied half-life in days.
    #[serde(default, rename = "boost_recency_days", alias = "boostRecencyDays")]
    #[schema(example = 7.0)]
    boost_recency_days: Option<f32>,
    /// Apply salience boost.
    #[serde(default, rename = "boost_salience", alias = "boostSalience")]
    #[schema(example = true)]
    boost_salience: Option<bool>,
    /// Apply confidence boost.
    #[serde(default, rename = "boost_confidence", alias = "boostConfidence")]
    #[schema(example = true)]
    boost_confidence: Option<bool>,
    /// Apply contiguity boost.
    #[serde(default, rename = "boost_contiguity", alias = "boostContiguity")]
    #[schema(example = true)]
    boost_contiguity: Option<bool>,
}

/// Time-window controls for context-pack assembly.
#[derive(Debug, Default, Deserialize, ToSchema)]
struct ContextPackTimeControls {
    /// Keep entities learned at or after this Unix timestamp.
    #[serde(default)]
    #[schema(example = 1_782_357_600_u64)]
    since: Option<u64>,
    /// Occurrence window start, inclusive.
    #[serde(default, rename = "occurred_start", alias = "occurredStart")]
    #[schema(example = 1_782_357_600_u64)]
    occurred_start: Option<u64>,
    /// Occurrence window end, inclusive.
    #[serde(default, rename = "occurred_end", alias = "occurredEnd")]
    #[schema(example = 1_782_357_900_u64)]
    occurred_end: Option<u64>,
    /// Learned-at window start, inclusive.
    #[serde(default, rename = "learned_start", alias = "learnedStart")]
    #[schema(example = 1_782_357_600_u64)]
    learned_start: Option<u64>,
    /// Learned-at window end, inclusive.
    #[serde(default, rename = "learned_end", alias = "learnedEnd")]
    #[schema(example = 1_782_357_900_u64)]
    learned_end: Option<u64>,
}

/// Per-kind retrieval item budget for context-pack assembly.
#[derive(Debug, Default, Deserialize, ToSchema)]
struct ContextPackRetrievalBudgetControls {
    #[serde(default)]
    #[schema(example = 4)]
    claims: Option<usize>,
    #[serde(default)]
    #[schema(example = 2)]
    turns: Option<usize>,
    #[serde(default)]
    #[schema(example = 2)]
    summaries: Option<usize>,
    #[serde(default)]
    #[schema(example = 1)]
    facets: Option<usize>,
    #[serde(default)]
    #[schema(example = 1)]
    other: Option<usize>,
    #[serde(default, rename = "selected_edges", alias = "selectedEdges")]
    #[schema(example = 50)]
    selected_edges: Option<usize>,
}

/// Token and item budget controls for context-pack assembly.
#[derive(Debug, Default, Deserialize, ToSchema)]
struct ContextPackBudgetControls {
    /// Serialized token budget for callers that request serialized packs downstream.
    #[serde(default, rename = "token_budget", alias = "tokenBudget")]
    #[schema(example = 4000)]
    token_budget: Option<usize>,
    /// Per-item token cap for context-pack serialization; 0 disables it.
    #[serde(default, rename = "max_item_tokens", alias = "maxItemTokens")]
    #[schema(example = 512)]
    max_item_tokens: Option<usize>,
    /// Maximum field characters before serialization truncation.
    #[serde(default, rename = "max_field_chars", alias = "maxFieldChars")]
    #[schema(example = 500)]
    max_field_chars: Option<usize>,
    /// Per-kind retrieval item budgets before final result truncation.
    #[serde(default)]
    retrieval: Option<ContextPackRetrievalBudgetControls>,
}

/// Context-pack request on the canonical core route.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "query": "blue hallway",
    "limit": 10,
    "include_edges": true,
    "edge_hop": 1,
    "view": "full"
}))]
struct CoreContextPackRequest {
    /// Optional BM25 text query.
    #[serde(default)]
    #[schema(example = "blue hallway")]
    query: Option<String>,
    /// Optional vector query.
    #[serde(default, rename = "query_vector", alias = "queryVector")]
    #[schema(example = json!([0.1, 0.2, 0.3, 0.4]))]
    query_vector: Option<Vec<f32>>,
    /// Maximum primary candidates to retrieve.
    #[serde(default = "default_limit")]
    #[schema(default = default_limit, example = 10)]
    limit: usize,
    /// Whether to include hydrated fields. Defaults to true.
    #[serde(default = "default_true")]
    #[schema(default = default_true, example = true)]
    hydrate: bool,
    /// Whether to include edge records in hydrated entities.
    #[serde(default, rename = "include_edges", alias = "includeEdges")]
    #[schema(example = true)]
    include_edges: bool,
    /// Edge expansion depth for neighbor hydration.
    #[serde(default, rename = "edge_hop", alias = "edgeHop")]
    #[schema(example = 1)]
    edge_hop: u32,
    /// Maximum neighbors to hydrate during edge expansion.
    #[serde(
        default = "default_context_neighbors",
        rename = "max_neighbors",
        alias = "maxNeighbors"
    )]
    #[schema(default = default_context_neighbors, example = 50)]
    max_neighbors: usize,
    /// Whether to include vectors in hydrated entities.
    #[serde(default, rename = "include_vectors", alias = "includeVectors")]
    #[schema(example = false)]
    include_vectors: bool,
    /// Field profile for hydrated fields. Defaults to standard.
    #[serde(default)]
    #[schema(example = "standard")]
    view: Option<View>,
    /// Optional nested depth controls. Overrides top-level edge_hop/max_neighbors when set.
    #[serde(default)]
    depth: Option<ContextPackDepthControls>,
    /// Optional nested ranking/projection policy controls.
    #[serde(default)]
    policy: Option<ContextPackPolicyControls>,
    /// Optional time-window filters.
    #[serde(default)]
    time: Option<ContextPackTimeControls>,
    /// Optional retrieval and serialization budget controls.
    #[serde(default)]
    budget: Option<ContextPackBudgetControls>,
}

/// Hydrated context edge.
#[derive(Debug, Serialize, ToSchema)]
struct CoreContextEdge {
    /// Numeric edge-kind discriminant.
    #[schema(example = 1)]
    kind: u8,
    /// Hex target entity id.
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    target: String,
    /// Target short id when the target is present in the same context pack.
    #[serde(rename = "target_short_id", skip_serializing_if = "Option::is_none")]
    #[schema(example = "tn2")]
    target_short_id: Option<String>,
    /// Edge weight.
    #[schema(example = 1.0)]
    weight: f32,
    /// Edge creation timestamp in Unix seconds.
    #[schema(example = 1782357635_u64)]
    created_at: u64,
    /// Optional edge VAD payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    vad: Option<VadPayload>,
}

/// Hydrated context entity.
#[derive(Debug, Serialize, ToSchema)]
struct CoreContextEntity {
    /// Hex entity id.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: String,
    /// Short id allocated by the vault, or hex fallback when no short id exists.
    #[serde(rename = "short_id")]
    #[schema(example = "tn1")]
    short_id: String,
    /// One-byte content hash as two lowercase hex digits.
    #[serde(rename = "content_hash")]
    #[schema(example = "a7")]
    content_hash: String,
    /// Numeric entity type byte.
    #[schema(example = 1)]
    entity_type: u8,
    /// Retrieval score.
    #[schema(example = 0.87)]
    score: f32,
    /// Hydrated fields when requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    fields: Option<BTreeMap<String, Value>>,
    /// Hydrated edges when requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    edges: Option<Vec<CoreContextEdge>>,
    /// Stored vector when requested and present.
    #[serde(skip_serializing_if = "Option::is_none")]
    vector: Option<Vec<f32>>,
}

/// Context-pack item accounting.
#[derive(Debug, Serialize, ToSchema)]
struct CoreContextPackItemAccounting {
    /// Number of items affected.
    #[schema(example = 0)]
    count: usize,
    /// Accounting reason.
    #[schema(example = "token_budget")]
    reason: String,
}

/// Context-pack stats.
#[derive(Debug, Serialize, ToSchema)]
struct CoreContextPackStats {
    /// Candidate count considered by the pack.
    #[schema(example = 1)]
    candidates_considered: usize,
    /// Retrieval signals used.
    signals_used: Vec<String>,
    /// Query execution duration in microseconds.
    #[schema(example = 1000_u64)]
    query_time_us: u64,
    /// Primary entities hydrated.
    #[schema(example = 1)]
    entities_hydrated: usize,
    /// Neighbor entities hydrated.
    #[schema(example = 0)]
    neighbors_hydrated: usize,
    /// Vector-only candidates dampened by cosine-ghost suppression.
    #[schema(example = 0)]
    cosine_ghosts_dampened: usize,
    /// Claims suppressed by read-path gates.
    #[schema(example = 0)]
    claims_suppressed: usize,
    /// Item truncation accounting.
    items_truncated: CoreContextPackItemAccounting,
    /// Item drop accounting.
    items_dropped: CoreContextPackItemAccounting,
}

/// Typed context-pack result state.
#[derive(Debug, Serialize, ToSchema)]
struct CoreContextPackState {
    /// Stable state discriminator.
    kind: CoreContextPackStateKind,
    /// Empty-result reason when the pack did not surface entities.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<CoreContextPackStateReason>,
    /// Total records in scope when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    total_in_scope: Option<usize>,
    /// Caller-facing hint from the retrieval layer.
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
}

/// Stable context-pack state discriminator.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum CoreContextPackStateKind {
    Ok,
    MissingData,
    LowConfidence,
}

/// Stable context-pack empty-result reason.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum CoreContextPackStateReason {
    FilterMatchedNone,
    NoData,
    AllActivated,
    BelowThreshold,
}

/// Score component that contributed to a context-pack result.
#[derive(Debug, Serialize, ToSchema)]
struct CoreContextPackScoreComponent {
    /// Retrieval signal name.
    signal: String,
    /// Rank within the signal.
    rank: u32,
    /// Raw signal score.
    score: f32,
}

/// Per-result context-pack score evidence.
#[derive(Debug, Serialize, ToSchema)]
struct CoreContextPackScoreEvidence {
    /// Hex entity id.
    result_id: String,
    /// Final rank after context-pack hydration.
    final_rank: u32,
    /// Final fused score.
    final_score: f32,
    /// Signal-level score components.
    components: Vec<CoreContextPackScoreComponent>,
}

/// Retrieval evidence attached to a context-pack response.
#[derive(Debug, Serialize, ToSchema)]
struct CoreContextPackEvidence {
    /// Whether the retrieval telemetry row was persisted and finalized.
    telemetry_persisted: bool,
    /// Retrieval telemetry run id when persistence succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    retrieval_run_id: Option<String>,
    /// Surfaced result ids recorded in telemetry.
    result_ids: Vec<String>,
    /// Final score evidence recorded in telemetry.
    scores: Vec<CoreContextPackScoreEvidence>,
}

/// Context-pack response envelope.
#[derive(Debug, Serialize, ToSchema)]
struct CoreContextPackResponse {
    /// Primary hydrated retrieval results.
    results: Vec<CoreContextEntity>,
    /// Neighbor entities hydrated through edge expansion.
    neighbors: Vec<CoreContextEntity>,
    /// Retrieval and hydration stats.
    stats: CoreContextPackStats,
    /// Typed missing-data / low-confidence state.
    state: CoreContextPackState,
    /// Retrieval evidence and score breakdown.
    evidence: CoreContextPackEvidence,
    /// Empty-result context when no entities surface.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    empty: Option<Value>,
}

/// Query parameters for core list endpoints.
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
struct CoreListQuery {
    /// Maximum number of entities to return.
    #[serde(default = "default_limit")]
    #[schema(default = default_limit, example = 10)]
    #[param(default = 10, example = 10)]
    limit: usize,
    /// Optional exclusive cursor id for entity-type scans.
    #[serde(default)]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    #[param(example = "0123456789abcdef0123456789abcdef")]
    after: Option<String>,
    /// Projection view. Defaults to summary.
    #[serde(default)]
    #[schema(example = "summary")]
    #[param(example = "summary")]
    view: Option<View>,
    /// Count precision for response metadata. List endpoints default to exact.
    #[serde(default, rename = "countMode", alias = "count_mode")]
    #[schema(example = "exact")]
    #[param(example = "exact")]
    count_mode: CountMode,
}

/// Generic core entity create request.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "body": { "name": "Dream session" },
    "text": [{ "field": "name", "value": "Dream session" }]
}))]
struct CoreCreateEntityRequest {
    /// Optional hex entity id. When omitted, the server generates an id.
    #[serde(default)]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: Option<String>,
    /// Occurrence start timestamp in Unix seconds. Defaults to `learned_at` or current server time.
    #[serde(default, rename = "occurred_start", alias = "occurredStart")]
    #[schema(example = 1782357600_u64)]
    occurred_start: Option<u64>,
    /// Occurrence end timestamp in Unix seconds. Defaults to `occurred_start`.
    #[serde(default, rename = "occurred_end", alias = "occurredEnd")]
    #[schema(example = 1782357600_u64)]
    occurred_end: Option<u64>,
    /// Learned-at timestamp in Unix seconds. Defaults to current server time.
    #[serde(default, rename = "learned_at", alias = "learnedAt")]
    #[schema(example = 1782357635_u64)]
    learned_at: Option<u64>,
    /// JSON body encoded into the vault's msgpack entity payload.
    #[schema(value_type = Object, example = json!({"name": "Dream session"}))]
    body: Value,
    /// Optional explicit text index fields. When omitted, top-level string body fields are indexed.
    #[serde(default)]
    text: Option<Vec<CoreTextField>>,
}

/// Core turn create request.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "body": { "txt": "I saw a blue hallway door.", "spkr": "user", "at": 1782357600_u64 },
    "text": [{ "field": "body", "value": "I saw a blue hallway door." }]
}))]
struct CoreCreateTurnRequest {
    /// Optional hex TURN id. When omitted, the server generates an id.
    #[serde(default)]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: Option<String>,
    /// Occurrence start timestamp in Unix seconds. Defaults to `learned_at` or current server time.
    #[serde(default, rename = "occurred_start", alias = "occurredStart")]
    #[schema(example = 1782357600_u64)]
    occurred_start: Option<u64>,
    /// Occurrence end timestamp in Unix seconds. Defaults to `occurred_start`.
    #[serde(default, rename = "occurred_end", alias = "occurredEnd")]
    #[schema(example = 1782357600_u64)]
    occurred_end: Option<u64>,
    /// Learned-at timestamp in Unix seconds. Defaults to current server time.
    #[serde(default, rename = "learned_at", alias = "learnedAt")]
    #[schema(example = 1782357635_u64)]
    learned_at: Option<u64>,
    /// JSON body encoded into the vault's msgpack TURN payload.
    #[schema(value_type = Object, example = json!({"txt": "I saw a blue hallway door."}))]
    body: Value,
    /// Optional explicit text index fields. When omitted, top-level string body fields are indexed.
    #[serde(default)]
    text: Option<Vec<CoreTextField>>,
}

/// Response from core conversation/turn create routes.
#[derive(Debug, Serialize, ToSchema)]
struct CoreEntityWriteResponse {
    /// Hex entity id written by the route.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: String,
    /// Numeric entity type byte.
    #[schema(example = 1)]
    entity_type: u8,
    /// Projected entity body after write.
    #[schema(value_type = Object)]
    item: Value,
}

/// Commit a core entity batch.
#[utoipa::path(
    post,
    path = "/v1/core/batch",
    request_body(content = CoreBatchRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Batch committed atomically.", body = CoreBatchResponse, content_type = "application/json"),
        (status = 400, description = "Malformed batch or invalid entity body.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:write.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Batch commit failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn core_batch(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CoreBatchRequest>, JsonRejection>,
) -> Result<Json<CoreBatchResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let req = json_payload(payload)?;
    if req.entities.len() > CORE_MAX_BATCH_ENTITIES {
        return Err(ApiError::bad_request(
            format!("entities must contain at most {CORE_MAX_BATCH_ENTITIES} entries"),
            Some("entities"),
        )
        .into());
    }

    let mut batch = server.vault.batch();
    let mut entities = Vec::with_capacity(req.entities.len());
    for entity in req.entities {
        let id = parse_optional_entity_id(entity.id.as_deref(), "id")?;
        let timestamps = core_entity_timestamps(
            entity.occurred_start,
            entity.occurred_end,
            entity.learned_at,
        )?;
        batch = stage_core_entity_put(
            batch,
            &id,
            entity.entity_type,
            timestamps,
            &entity.body,
            entity.text.as_deref(),
        )?;
        entities.push(CoreBatchEntityResult {
            id: id.to_hex(),
            entity_type: entity.entity_type,
        });
    }

    batch.commit().map_err(|error| {
        tracing::error!(error = %error, "core batch commit failed");
        core_engine_error("core batch commit failed", error)
    })?;

    Ok(Json(CoreBatchResponse {
        count: entities.len(),
        entities,
    }))
}

/// Query core memory through text and/or vector retrieval.
#[utoipa::path(
    post,
    path = "/v1/core/query",
    request_body(content = CoreQueryRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Projected query results.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed query request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Query failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn core_query(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CoreQueryRequest>, JsonRejection>,
) -> Result<Json<SearchResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let req = json_payload(payload)?;
    let query = non_empty_query(req.query.as_deref());
    validate_core_query_seeds(query, req.query_vector.as_deref())?;

    let view = req.view.unwrap_or(View::Summary);
    let count_mode = req.count_mode.for_search_response();
    let fetch_limit = search_fetch_limit(count_mode, req.limit);
    let results = run_core_query(
        &server.vault,
        query,
        req.query_vector.as_deref(),
        fetch_limit,
    )
    .map_err(|error| {
        tracing::error!(error = %error, "core query failed");
        core_engine_error("core query failed", error)
    })?;
    let total = results.len();
    let response = search_response(&server.vault, results, view, req.limit)?;
    let meta = search_meta(count_mode, total);

    Ok(Json(PaginatedResponse::new(response, None, meta)))
}

/// Hydrate an entity by context-pack short reference.
#[utoipa::path(
    post,
    path = "/v1/core/hydrate",
    request_body(content = CoreHydrateRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Short ref resolved to a live or deleted entity.", body = CoreHydrateResponse, content_type = "application/json"),
        (status = 400, description = "Malformed short ref.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Short ref was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Hydrate lookup failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn core_hydrate(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CoreHydrateRequest>, JsonRejection>,
) -> Result<Json<CoreHydrateResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let req = json_payload(payload)?;
    let (short_id, content_hash) = parse_short_ref_request(&req)?;
    let content_hash_hex = format!("{content_hash:02x}");
    let view = req.view.unwrap_or(View::Full);
    let Some(response) = hydrate_short_id_response(&server, short_id.clone(), content_hash, view)?
    else {
        return Err(ApiError::not_found(
            "short_id",
            Some(&format!("{short_id}:{content_hash_hex}")),
        )
        .into());
    };

    Ok(Json(response))
}

/// Batch-hydrate entities by context-pack short references.
#[utoipa::path(
    post,
    path = "/v1/core/batch/shortId/hydrate",
    request_body(content = CoreBatchShortIdHydrateRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Short refs hydrated with per-item typed results/errors.", body = CoreBatchShortIdHydrateResponse, content_type = "application/json"),
        (status = 400, description = "Malformed batch request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Hydrate lookup failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn core_batch_short_id_hydrate(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CoreBatchShortIdHydrateRequest>, JsonRejection>,
) -> Result<Json<CoreBatchShortIdHydrateResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let req = json_payload(payload)?;
    if req.refs.is_empty() {
        return Err(ApiError::bad_request("refs must not be empty", Some("refs")).into());
    }
    if req.refs.len() > CORE_MAX_BATCH_ENTITIES {
        return Err(ApiError::bad_request(
            format!("refs must contain at most {CORE_MAX_BATCH_ENTITIES} entries"),
            Some("refs"),
        )
        .into());
    }

    let view = req.view.unwrap_or(View::Full);
    let mut results = Vec::with_capacity(req.refs.len());
    for reference in req.refs {
        let item = match parse_short_ref(&reference) {
            Ok((short_id, content_hash)) => {
                match hydrate_short_id_response(&server, short_id, content_hash, view)? {
                    Some(result) => CoreBatchShortIdHydrateItem {
                        reference,
                        outcome: match result.status {
                            CoreHydrateStatus::Live => CoreShortIdHydrateOutcome::Live,
                            CoreHydrateStatus::Deleted => CoreShortIdHydrateOutcome::Deleted,
                        },
                        result: Some(result),
                        error: None,
                    },
                    None => CoreBatchShortIdHydrateItem {
                        reference,
                        outcome: CoreShortIdHydrateOutcome::NotFound,
                        result: None,
                        error: Some(CoreShortIdHydrateError {
                            kind: CoreShortIdHydrateErrorKind::NotFound,
                            message: "short_id was not found".to_owned(),
                            field: Some("ref".to_owned()),
                        }),
                    },
                }
            }
            Err(error) => CoreBatchShortIdHydrateItem {
                reference,
                outcome: CoreShortIdHydrateOutcome::MalformedShortId,
                result: None,
                error: Some(CoreShortIdHydrateError {
                    kind: CoreShortIdHydrateErrorKind::MalformedShortId,
                    message: error.message().to_owned(),
                    field: match error.details() {
                        ApiErrorDetails::BadRequest { field } => field.clone(),
                        _ => None,
                    },
                }),
            },
        };
        results.push(item);
    }

    Ok(Json(CoreBatchShortIdHydrateResponse { results }))
}

/// Return renderer-ready supersession timeline data for one memory record.
#[utoipa::path(
    get,
    path = "/v1/core/memory/{id}/timeline",
    params(
        (
            "id" = String,
            Path,
            description = "Hex entity id whose supersession chain should be rendered.",
            example = "0123456789abcdef0123456789abcdef"
        ),
        ViewQuery
    ),
    responses(
        (status = 200, description = "Stable ordered memory supersession timeline.", body = CoreMemoryTimelineResponse, content_type = "application/json"),
        (status = 400, description = "Malformed entity id or view.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Anchor entity was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Timeline lookup failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn core_memory_timeline(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(id_hex): Path<String>,
    query: Result<Query<ViewQuery>, QueryRejection>,
) -> Result<Json<CoreMemoryTimelineResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let id = parse_entity_id_param(&id_hex, "id")?;
    let params = query_params(query)?;
    let view = params.view.unwrap_or(View::Summary);
    let timeline = server.vault.memory_timeline(&id).map_err(|error| {
        tracing::error!(error = %error, id = %id.to_hex(), "core memory timeline failed");
        core_engine_error("core memory timeline failed", error)
    })?;

    if timeline.records.len() == 1
        && timeline.records[0].state == oneiron::MemoryTimelineRecordState::Missing
    {
        return Err(ApiError::not_found("entity", Some(&id.to_hex())).into());
    }

    Ok(Json(core_memory_timeline_response(
        &server.vault,
        timeline,
        view,
    )?))
}

/// Execute a named memory verb after resolving it to a typed vault operation.
#[utoipa::path(
    post,
    path = "/v1/core/memory/verbs/{verb}",
    params(
        (
            "verb" = String,
            Path,
            description = "Named memory verb: remember, supersede, retract, delete/forget, or hard_delete/erase.",
            example = "supersede"
        )
    ),
    request_body(content = CoreMemoryVerbRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Named verb resolved and executed as a typed operation.", body = CoreMemoryVerbResponse, content_type = "application/json"),
        (status = 400, description = "Malformed verb request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:write.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Referenced entity was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Memory verb failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn core_memory_verb(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(verb_name): Path<String>,
    payload: Result<Json<CoreMemoryVerbRequest>, JsonRejection>,
) -> Result<Json<CoreMemoryVerbResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let verb = oneiron::NamedMemoryVerb::parse(&verb_name).ok_or_else(|| {
        ApiError::bad_request(
            "verb must be one of remember (put), supersede (replace/revise), retract (withdraw), delete (forget), hard_delete (erase/purge)",
            Some("verb"),
        )
    })?;
    let req = json_payload(payload)?;
    let operation = core_memory_operation_kind(verb.operation_kind());

    match verb {
        oneiron::NamedMemoryVerb::Remember => {
            let entity = req.entity.ok_or_else(|| {
                ApiError::bad_request("entity is required for remember", Some("entity"))
            })?;
            let id = parse_optional_entity_id(entity.id.as_deref(), "entity.id")?;
            let timestamps = core_entity_timestamps(
                entity.occurred_start,
                entity.occurred_end,
                entity.learned_at,
            )?;
            let batch = server.vault.batch();
            stage_core_entity_put(
                batch,
                &id,
                entity.entity_type,
                timestamps,
                &entity.body,
                entity.text.as_deref(),
            )?
            .commit()
            .map_err(|error| {
                tracing::error!(error = %error, id = %id.to_hex(), "core memory remember failed");
                core_engine_error("core memory remember failed", error)
            })?;

            Ok(Json(CoreMemoryVerbResponse {
                verb: verb.canonical_name().to_owned(),
                operation,
                at: None,
                id: Some(id.to_hex()),
                new_id: None,
                old_id: None,
                entity: Some(CoreBatchEntityResult {
                    id: id.to_hex(),
                    entity_type: entity.entity_type,
                }),
                delete: None,
            }))
        }
        oneiron::NamedMemoryVerb::Supersede => {
            let new_id = parse_required_entity_id(req.new_id.as_deref(), "new_id")?;
            let old_id = parse_required_entity_id(req.old_id.as_deref(), "old_id")?;
            let at = req.at.unwrap_or_else(unix_seconds_now);
            server
                .vault
                .supersede_claim(&new_id, &old_id, at)
                .map_err(|error| {
                    tracing::error!(
                        error = %error,
                        new_id = %new_id.to_hex(),
                        old_id = %old_id.to_hex(),
                        "core memory supersede failed"
                    );
                    core_engine_error("core memory supersede failed", error)
                })?;

            Ok(Json(CoreMemoryVerbResponse {
                verb: verb.canonical_name().to_owned(),
                operation,
                at: Some(at),
                id: None,
                new_id: Some(new_id.to_hex()),
                old_id: Some(old_id.to_hex()),
                entity: None,
                delete: None,
            }))
        }
        oneiron::NamedMemoryVerb::Retract => {
            let id = parse_required_entity_id(req.id.as_deref(), "id")?;
            let at = req.at.unwrap_or_else(unix_seconds_now);
            server.vault.retract_claim(&id, at).map_err(|error| {
                tracing::error!(error = %error, id = %id.to_hex(), "core memory retract failed");
                core_engine_error("core memory retract failed", error)
            })?;

            Ok(Json(CoreMemoryVerbResponse {
                verb: verb.canonical_name().to_owned(),
                operation,
                at: Some(at),
                id: Some(id.to_hex()),
                new_id: None,
                old_id: None,
                entity: None,
                delete: None,
            }))
        }
        oneiron::NamedMemoryVerb::Delete | oneiron::NamedMemoryVerb::HardDelete => {
            if req.at.is_some() {
                return Err(ApiError::bad_request(
                    "at is not supported for delete verbs; deletion time is recorded by the vault",
                    Some("at"),
                )
                .into());
            }
            let id = parse_required_entity_id(req.id.as_deref(), "id")?;
            let (reason, response_reason) = core_memory_delete_reason(verb, req.reason)?;
            let outcome = server
                .vault
                .delete_entity_with_reason(&id, reason)
                .map_err(|error| {
                    tracing::error!(error = %error, id = %id.to_hex(), "core memory delete failed");
                    core_engine_error("core memory delete failed", error)
                })?;

            Ok(Json(CoreMemoryVerbResponse {
                verb: verb.canonical_name().to_owned(),
                operation,
                at: None,
                id: Some(id.to_hex()),
                new_id: None,
                old_id: None,
                entity: None,
                delete: Some(CoreMemoryVerbDeleteOutcome {
                    existed: outcome.existed,
                    reason: response_reason,
                    hard: matches!(
                        reason,
                        oneiron::DeleteReason::UserHardDelete
                            | oneiron::DeleteReason::GdprDelete
                            | oneiron::DeleteReason::PolicyDelete
                    ),
                    receipt_id: outcome.receipt_id.map(|id| id.to_hex()),
                    sweep_key: outcome.sweep_key.as_deref().map(hex_bytes),
                }),
            }))
        }
    }
}

fn core_memory_timeline_response(
    vault: &oneiron::Vault,
    timeline: oneiron::MemoryTimeline,
    view: View,
) -> Result<CoreMemoryTimelineResponse, ApiError> {
    let mut records = Vec::with_capacity(timeline.records.len());
    for record in timeline.records {
        let item = if matches!(
            record.state,
            oneiron::MemoryTimelineRecordState::Live
                | oneiron::MemoryTimelineRecordState::Superseded
                | oneiron::MemoryTimelineRecordState::Retracted
        ) {
            projection::project_entity(vault, &record.id, view).map_err(|error| {
                tracing::error!(error = %error, id = %record.id.to_hex(), "core memory timeline projection failed");
                core_engine_error("core memory timeline projection failed", error)
            })?
        } else {
            None
        };

        records.push(CoreMemoryTimelineRecord {
            id: record.id.to_hex(),
            state: core_memory_timeline_state(record.state),
            entity_type: record.entity_type,
            occurred_start: record.occurred_start,
            occurred_end: record.occurred_end,
            learned_at: record.learned_at,
            body_bytes: record.body_bytes,
            deletion: record.deletion.map(core_hydrate_deletion_metadata),
            supersedes: record
                .supersedes
                .into_iter()
                .map(|id| id.to_hex())
                .collect(),
            superseded_by: record
                .superseded_by
                .into_iter()
                .map(|id| id.to_hex())
                .collect(),
            item,
        });
    }

    Ok(CoreMemoryTimelineResponse {
        anchor_id: timeline.anchor.to_hex(),
        records,
    })
}

fn core_memory_timeline_state(
    state: oneiron::MemoryTimelineRecordState,
) -> CoreMemoryTimelineRecordState {
    match state {
        oneiron::MemoryTimelineRecordState::Live => CoreMemoryTimelineRecordState::Live,
        oneiron::MemoryTimelineRecordState::Superseded => CoreMemoryTimelineRecordState::Superseded,
        oneiron::MemoryTimelineRecordState::Retracted => CoreMemoryTimelineRecordState::Retracted,
        oneiron::MemoryTimelineRecordState::Deleted => CoreMemoryTimelineRecordState::Deleted,
        oneiron::MemoryTimelineRecordState::Missing => CoreMemoryTimelineRecordState::Missing,
    }
}

fn core_memory_operation_kind(kind: oneiron::MemoryOperationKind) -> CoreMemoryOperationKind {
    match kind {
        oneiron::MemoryOperationKind::PutEntity => CoreMemoryOperationKind::PutEntity,
        oneiron::MemoryOperationKind::SupersedeClaim => CoreMemoryOperationKind::SupersedeClaim,
        oneiron::MemoryOperationKind::RetractClaim => CoreMemoryOperationKind::RetractClaim,
        oneiron::MemoryOperationKind::DeleteEntity => CoreMemoryOperationKind::DeleteEntity,
    }
}

fn parse_required_entity_id(
    value: Option<&str>,
    field: &'static str,
) -> Result<oneiron::EntityId, ApiError> {
    let Some(value) = value else {
        return Err(ApiError::bad_request(
            format!("{field} is required"),
            Some(field),
        ));
    };
    parse_entity_id_param(value, field)
}

fn core_memory_delete_reason(
    verb: oneiron::NamedMemoryVerb,
    requested: Option<CoreMemoryVerbDeleteReason>,
) -> Result<(oneiron::DeleteReason, CoreMemoryVerbDeleteReason), ApiError> {
    let response_reason = requested.unwrap_or(match verb {
        oneiron::NamedMemoryVerb::HardDelete => CoreMemoryVerbDeleteReason::UserHard,
        _ => CoreMemoryVerbDeleteReason::User,
    });
    let reason = match response_reason {
        CoreMemoryVerbDeleteReason::User => oneiron::DeleteReason::UserDelete,
        CoreMemoryVerbDeleteReason::UserHard => oneiron::DeleteReason::UserHardDelete,
        CoreMemoryVerbDeleteReason::Gdpr => oneiron::DeleteReason::GdprDelete,
        CoreMemoryVerbDeleteReason::Policy => oneiron::DeleteReason::PolicyDelete,
    };
    match (verb, response_reason) {
        (oneiron::NamedMemoryVerb::Delete, CoreMemoryVerbDeleteReason::User) => {}
        (oneiron::NamedMemoryVerb::Delete, _) => {
            return Err(ApiError::bad_request(
                "delete only accepts user_delete; use hard_delete for hard-delete reasons",
                Some("reason"),
            ));
        }
        (
            oneiron::NamedMemoryVerb::HardDelete,
            CoreMemoryVerbDeleteReason::UserHard
            | CoreMemoryVerbDeleteReason::Gdpr
            | CoreMemoryVerbDeleteReason::Policy,
        ) => {}
        (oneiron::NamedMemoryVerb::HardDelete, CoreMemoryVerbDeleteReason::User) => {
            return Err(ApiError::bad_request(
                "hard_delete requires user_hard_delete, gdpr_delete, or policy_delete",
                Some("reason"),
            ));
        }
        _ => {}
    }
    Ok((reason, response_reason))
}

fn hydrate_short_id_response(
    server: &SyncServer,
    short_id: String,
    content_hash: u8,
    view: View,
) -> Result<Option<CoreHydrateResponse>, ApiError> {
    let content_hash_hex = format!("{content_hash:02x}");
    let result = server
        .vault
        .hydrate_short_id(&short_id, content_hash)
        .map_err(|error| {
            tracing::error!(error = %error, short_id, content_hash = content_hash_hex, "core short hydrate failed");
            core_engine_error("core short hydrate failed", error)
        })?;

    let Some(oneiron::HydratedShortId {
        id,
        entity_type,
        learned_at,
        deletion,
        body,
    }) = result
    else {
        return Ok(None);
    };

    let Some(body) = body else {
        return Ok(Some(CoreHydrateResponse {
            status: CoreHydrateStatus::Deleted,
            short_id,
            content_hash: content_hash_hex,
            id: Some(id.to_hex()),
            entity_type: (entity_type != 0).then_some(entity_type),
            deletion: deletion.map(core_hydrate_deletion_metadata),
            item: None,
        }));
    };

    let item = projection::project_entity_parts(&id, entity_type, learned_at, &body, view);
    Ok(Some(CoreHydrateResponse {
        status: CoreHydrateStatus::Live,
        short_id,
        content_hash: content_hash_hex,
        id: Some(id.to_hex()),
        entity_type: Some(entity_type),
        deletion: None,
        item: Some(item),
    }))
}

fn core_hydrate_deletion_metadata(
    deletion: oneiron::HydratedShortIdDeletion,
) -> CoreHydrateDeletionMetadata {
    CoreHydrateDeletionMetadata {
        source: match deletion.source {
            oneiron::HydratedShortIdDeletionSource::Tombstone => {
                CoreHydrateDeletionSource::Tombstone
            }
            oneiron::HydratedShortIdDeletionSource::PendingTombstone => {
                CoreHydrateDeletionSource::PendingTombstone
            }
            oneiron::HydratedShortIdDeletionSource::DanglingShortId => {
                CoreHydrateDeletionSource::DanglingShortId
            }
        },
        reason: deletion.reason.map(|reason| match reason {
            oneiron::HydratedShortIdDeletionReason::UserDelete => CoreHydrateDeletionReason::User,
            oneiron::HydratedShortIdDeletionReason::UserHardDelete => {
                CoreHydrateDeletionReason::UserHard
            }
            oneiron::HydratedShortIdDeletionReason::GdprDelete => CoreHydrateDeletionReason::Gdpr,
            oneiron::HydratedShortIdDeletionReason::PolicyDelete => {
                CoreHydrateDeletionReason::Policy
            }
        }),
        deleted_at: deletion.deleted_at,
        request_id: deletion.request_id,
        hard: deletion.hard,
    }
}

/// Assemble a context pack from existing retrieval and hydration APIs.
#[utoipa::path(
    post,
    path = "/v1/core/context-pack",
    request_body(content = CoreContextPackRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Context pack assembled.", body = CoreContextPackResponse, content_type = "application/json"),
        (status = 400, description = "Malformed context-pack request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Context-pack assembly failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn core_context_pack(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CoreContextPackRequest>, JsonRejection>,
) -> Result<Json<CoreContextPackResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let req = json_payload(payload)?;
    let query = non_empty_query(req.query.as_deref());
    validate_core_query_seeds(query, req.query_vector.as_deref())?;
    let (edge_hop, edge_hop_field, max_neighbors, max_neighbors_field) =
        resolved_context_pack_depth(req.depth.as_ref(), req.edge_hop, req.max_neighbors);
    validate_context_pack_depth(edge_hop, edge_hop_field, max_neighbors, max_neighbors_field)?;
    let hydrate = req
        .policy
        .as_ref()
        .and_then(|policy| policy.hydrate)
        .unwrap_or(req.hydrate);
    let include_edges = req
        .policy
        .as_ref()
        .and_then(|policy| policy.include_edges)
        .unwrap_or(req.include_edges);
    let include_vectors = req
        .policy
        .as_ref()
        .and_then(|policy| policy.include_vectors)
        .unwrap_or(req.include_vectors);
    let view = req
        .policy
        .as_ref()
        .and_then(|policy| policy.view)
        .or(req.view)
        .unwrap_or(View::Standard);
    let projection = context_pack_json_projection_config(view, req.budget.as_ref(), 0);

    let mut builder = server
        .vault
        .context_pack()
        .limit(req.limit)
        .hydrate(hydrate)
        .include_edges(include_edges)
        .edge_hop(edge_hop)
        .max_neighbors(max_neighbors)
        .include_vectors(include_vectors)
        .field_profile(projection.profile);
    if let Some(query) = query {
        builder = builder.search_text(query, req.limit);
    }
    if let Some(vector) = req.query_vector.as_deref() {
        builder = builder.search_vector(vector, req.limit);
    }
    builder = apply_context_pack_policy(builder, req.policy.as_ref())?;
    builder = apply_context_pack_time(builder, req.time.as_ref())?;
    builder = apply_context_pack_budget(builder, req.budget.as_ref(), 0, req.limit, max_neighbors)?;

    Ok(Json(run_context_pack_builder(
        &server.vault,
        builder,
        projection,
        "core context-pack failed",
    )?))
}

/// List conversation entities.
#[utoipa::path(
    get,
    path = "/v1/core/conversations",
    params(CoreListQuery),
    responses(
        (status = 200, description = "Conversation entities.", body = Object, content_type = "application/json"),
        (status = 400, description = "Invalid list query.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Conversation listing failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn list_core_conversations(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<CoreListQuery>, QueryRejection>,
) -> Result<Json<SearchResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let params = query_params(query)?;
    core_list_entities_by_type(&server.vault, ENTITY_TYPE_CONVERSATION, params)
}

/// Create a conversation entity.
#[utoipa::path(
    post,
    path = "/v1/core/conversations",
    request_body(content = CoreCreateEntityRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Conversation created.", body = CoreEntityWriteResponse, content_type = "application/json"),
        (status = 400, description = "Malformed create request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:write.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Conversation create failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn create_core_conversation(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CoreCreateEntityRequest>, JsonRejection>,
) -> Result<Json<CoreEntityWriteResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let req = json_payload(payload)?;
    write_core_entity(
        &server.vault,
        CoreEntityWriteInput {
            id: req.id.as_deref(),
            entity_type: ENTITY_TYPE_CONVERSATION,
            occurred_start: req.occurred_start,
            occurred_end: req.occurred_end,
            learned_at: req.learned_at,
            body: &req.body,
            text: req.text.as_deref(),
        },
    )
}

/// List turns attached to a conversation.
#[utoipa::path(
    get,
    path = "/v1/core/conversations/{conversation_id}/turns",
    params(
        ("conversation_id" = String, Path, description = "Hex conversation id."),
        CoreListQuery
    ),
    responses(
        (status = 200, description = "Conversation turns.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed conversation id or query.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Conversation was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Turn listing failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn list_core_conversation_turns(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(conversation_id): Path<String>,
    query: Result<Query<CoreListQuery>, QueryRejection>,
) -> Result<Json<SearchResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    require_entity_type(
        &server,
        &conversation,
        ENTITY_TYPE_CONVERSATION,
        "conversation",
    )?;
    let params = query_params(query)?;
    core_list_conversation_turns(&server.vault, &conversation, params)
}

/// Create a turn inside a conversation.
#[utoipa::path(
    post,
    path = "/v1/core/conversations/{conversation_id}/turns",
    params(("conversation_id" = String, Path, description = "Hex conversation id.")),
    request_body(content = CoreCreateTurnRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Turn created and linked to conversation.", body = CoreEntityWriteResponse, content_type = "application/json"),
        (status = 400, description = "Malformed request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:write.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Conversation was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 409, description = "Child-of constraints rejected the turn create request; response uses INVALID_STATE.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Turn create failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn create_core_conversation_turn(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(conversation_id): Path<String>,
    payload: Result<Json<CoreCreateTurnRequest>, JsonRejection>,
) -> Result<Json<CoreEntityWriteResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    require_entity_type(
        &server,
        &conversation,
        ENTITY_TYPE_CONVERSATION,
        "conversation",
    )?;
    let req = json_payload(payload)?;
    let id = parse_optional_entity_id(req.id.as_deref(), "id")?;
    let timestamps = core_entity_timestamps(req.occurred_start, req.occurred_end, req.learned_at)?;
    let mut batch = server.vault.batch();
    batch = stage_core_entity_put(
        batch,
        &id,
        ENTITY_TYPE_TURN,
        timestamps,
        &req.body,
        req.text.as_deref(),
    )?
    .edge_checked(&id, &conversation, 1.0);
    batch.commit().map_err(|error| {
        tracing::error!(error = %error, "core turn create failed");
        core_engine_error("core turn create failed", error)
    })?;

    let item = projection::project_entity_parts(
        &id,
        ENTITY_TYPE_TURN,
        timestamps.learned_at,
        &encode_core_body(&req.body)?,
        View::Full,
    );
    Ok(Json(CoreEntityWriteResponse {
        id: id.to_hex(),
        entity_type: ENTITY_TYPE_TURN,
        item,
    }))
}

/// Read one turn entity by id.
#[utoipa::path(
    get,
    path = "/v1/core/turns/{turn_id}",
    params(
        ("turn_id" = String, Path, description = "Hex turn id."),
        ViewQuery
    ),
    responses(
        (status = 200, description = "Projected turn entity.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed turn id or view.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Turn was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Turn read failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
async fn get_core_turn(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(turn_id): Path<String>,
    query: Result<Query<ViewQuery>, QueryRejection>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let id = parse_entity_id_param(&turn_id, "turn_id")?;
    require_entity_type(&server, &id, ENTITY_TYPE_TURN, "turn")?;
    let params = query_params(query)?;
    let view = params.view.unwrap_or(View::Full);
    project_core_entity(&server.vault, &id, view)
}

#[derive(Clone, Copy)]
struct CoreEntityTimestamps {
    occurred: oneiron::TimeRange,
    learned_at: u64,
}

fn default_true() -> bool {
    true
}

fn default_context_neighbors() -> usize {
    50
}

fn parse_optional_entity_id(
    value: Option<&str>,
    field: &'static str,
) -> Result<oneiron::EntityId, ApiError> {
    value.map_or_else(
        || Ok(oneiron::EntityId::now()),
        |value| parse_entity_id_param(value, field),
    )
}

fn core_entity_timestamps(
    occurred_start: Option<u64>,
    occurred_end: Option<u64>,
    learned_at: Option<u64>,
) -> Result<CoreEntityTimestamps, ApiError> {
    let learned_at = learned_at.unwrap_or_else(unix_seconds_now);
    let start = occurred_start.unwrap_or(learned_at);
    let end = occurred_end.unwrap_or(start);
    if start > end {
        return Err(ApiError::bad_request(
            "occurred_start must be less than or equal to occurred_end",
            Some("occurred_start"),
        ));
    }
    Ok(CoreEntityTimestamps {
        occurred: oneiron::TimeRange { start, end },
        learned_at,
    })
}

fn encode_core_body(body: &Value) -> Result<Vec<u8>, ApiError> {
    rmp_serde::to_vec_named(body)
        .map_err(|_| ApiError::bad_request("body must be msgpack-encodable JSON", Some("body")))
}

fn stage_core_entity_put<'a>(
    batch: oneiron::BatchBuilder<'a>,
    id: &oneiron::EntityId,
    entity_type: u8,
    timestamps: CoreEntityTimestamps,
    body: &Value,
    text: Option<&[CoreTextField]>,
) -> Result<oneiron::BatchBuilder<'a>, ApiError> {
    let data = encode_core_body(body)?;
    let mut batch = batch.put(
        id,
        entity_type,
        timestamps.occurred,
        timestamps.learned_at,
        &data,
    );
    let text_fields = core_text_fields(text, body);
    if !text_fields.is_empty() {
        let refs: Vec<(&str, &str)> = text_fields
            .iter()
            .map(|(field, value)| (field.as_str(), value.as_str()))
            .collect();
        batch = batch.text(id, &refs);
    }
    Ok(batch)
}

fn core_text_fields(text: Option<&[CoreTextField]>, body: &Value) -> Vec<(String, String)> {
    if let Some(text) = text {
        return text
            .iter()
            .filter(|entry| !entry.field.is_empty() && !entry.value.is_empty())
            .map(|entry| (entry.field.clone(), entry.value.clone()))
            .collect();
    }

    let Value::Object(object) = body else {
        return Vec::new();
    };
    object
        .iter()
        .filter_map(|(key, value)| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(|value| (key.clone(), value.to_owned()))
        })
        .collect()
}

fn non_empty_query(query: Option<&str>) -> Option<&str> {
    query.map(str::trim).filter(|query| !query.is_empty())
}

fn validate_core_query_seeds(query: Option<&str>, vector: Option<&[f32]>) -> Result<(), ApiError> {
    if non_empty_query(query).is_none() && vector.is_none() {
        return Err(ApiError::bad_request(
            "query or query_vector is required",
            Some("query"),
        ));
    }
    if vector.is_some_and(|vector| vector.iter().any(|value| !value.is_finite())) {
        return Err(ApiError::bad_request(
            "query_vector values must be finite",
            Some("query_vector"),
        ));
    }
    Ok(())
}

fn resolved_context_pack_depth(
    depth: Option<&ContextPackDepthControls>,
    edge_hop: u32,
    max_neighbors: usize,
) -> (u32, &'static str, usize, &'static str) {
    let depth_edge_hop = depth.and_then(|depth| depth.edge_hop);
    let depth_max_neighbors = depth.and_then(|depth| depth.max_neighbors);
    (
        depth_edge_hop.unwrap_or(edge_hop),
        if depth_edge_hop.is_some() {
            "depth.edge_hop"
        } else {
            "edge_hop"
        },
        depth_max_neighbors.unwrap_or(max_neighbors),
        if depth_max_neighbors.is_some() {
            "depth.max_neighbors"
        } else {
            "max_neighbors"
        },
    )
}

fn validate_context_pack_depth(
    edge_hop: u32,
    edge_hop_field: &'static str,
    max_neighbors: usize,
    max_neighbors_field: &'static str,
) -> Result<(), ApiError> {
    if edge_hop > oneiron::context_pack::MAX_EDGE_HOP {
        return Err(ApiError::bad_request(
            format!(
                "edge_hop must be less than or equal to {}",
                oneiron::context_pack::MAX_EDGE_HOP
            ),
            Some(edge_hop_field),
        ));
    }
    if max_neighbors > oneiron::context_pack::MAX_CONTEXT_NEIGHBORS {
        return Err(ApiError::bad_request(
            format!(
                "max_neighbors must be less than or equal to {}",
                oneiron::context_pack::MAX_CONTEXT_NEIGHBORS
            ),
            Some(max_neighbors_field),
        ));
    }
    Ok(())
}

fn apply_context_pack_policy<'a>(
    mut builder: oneiron::ContextPackBuilder<'a>,
    policy: Option<&ContextPackPolicyControls>,
) -> Result<oneiron::ContextPackBuilder<'a>, ApiError> {
    let Some(policy) = policy else {
        return Ok(builder);
    };
    if let Some(half_life_days) = policy.boost_recency_days {
        if !half_life_days.is_finite() || half_life_days <= 0.0 {
            return Err(ApiError::bad_request(
                "boost_recency_days must be finite and positive",
                Some("policy.boost_recency_days"),
            ));
        }
        builder = builder.boost_recency(half_life_days);
    }
    if policy.boost_salience.unwrap_or(false) {
        builder = builder.boost_salience();
    }
    if policy.boost_confidence.unwrap_or(false) {
        builder = builder.boost_confidence();
    }
    if policy.boost_contiguity.unwrap_or(false) {
        builder = builder.boost_contiguity();
    }
    Ok(builder)
}

fn apply_context_pack_time<'a>(
    mut builder: oneiron::ContextPackBuilder<'a>,
    time: Option<&ContextPackTimeControls>,
) -> Result<oneiron::ContextPackBuilder<'a>, ApiError> {
    let Some(time) = time else {
        return Ok(builder);
    };
    let occurred_range = match (time.occurred_start, time.occurred_end) {
        (Some(start), Some(end)) if start <= end => Some((start, end)),
        (Some(_), Some(_)) => {
            return Err(ApiError::bad_request(
                "occurred_start must be less than or equal to occurred_end",
                Some("time.occurred_start"),
            ));
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(ApiError::bad_request(
                "occurred_start and occurred_end must be supplied together",
                Some("time"),
            ));
        }
        (None, None) => None,
    };
    let learned_range = match (time.learned_start, time.learned_end) {
        (Some(start), Some(end)) if start <= end => Some((start, end)),
        (Some(_), Some(_)) => {
            return Err(ApiError::bad_request(
                "learned_start must be less than or equal to learned_end",
                Some("time.learned_start"),
            ));
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(ApiError::bad_request(
                "learned_start and learned_end must be supplied together",
                Some("time"),
            ));
        }
        (None, None) => None,
    };
    if let (Some(since), Some((_, learned_end))) = (time.since, learned_range)
        && since > learned_end
    {
        return Err(ApiError::bad_request(
            "since must be less than or equal to learned_end",
            Some("time.since"),
        ));
    }
    if let Some(since) = time.since {
        builder = builder.filter_since(since);
    }
    if let Some((start, end)) = occurred_range {
        builder = builder.filter_occurred_range(start, end);
    }
    if let Some((start, end)) = learned_range {
        builder = builder.filter_learned_range(start, end);
    }
    Ok(builder)
}

fn apply_context_pack_budget<'a>(
    mut builder: oneiron::ContextPackBuilder<'a>,
    budget: Option<&ContextPackBudgetControls>,
    top_level_max_item_tokens: usize,
    limit: usize,
    default_selected_edges: usize,
) -> Result<oneiron::ContextPackBuilder<'a>, ApiError> {
    let max_item_tokens = budget
        .and_then(|budget| budget.max_item_tokens)
        .unwrap_or(top_level_max_item_tokens);
    if max_item_tokens > 0 {
        builder = builder.max_item_tokens(max_item_tokens);
    }
    let Some(budget) = budget else {
        return Ok(builder);
    };
    if let Some(token_budget) = budget.token_budget {
        builder = builder.token_budget(token_budget);
    }
    if let Some(max_field_chars) = budget.max_field_chars {
        builder = builder.max_field_chars(max_field_chars);
    }
    if let Some(retrieval) = budget.retrieval.as_ref() {
        if retrieval.selected_edges.is_some_and(|selected_edges| {
            selected_edges > oneiron::context_pack::MAX_CONTEXT_NEIGHBORS
        }) {
            return Err(ApiError::bad_request(
                format!(
                    "selected_edges must be less than or equal to {}",
                    oneiron::context_pack::MAX_CONTEXT_NEIGHBORS
                ),
                Some("budget.retrieval.selected_edges"),
            ));
        }
        let defaults = oneiron::ContextPackRetrievalBudget::from_limit(
            limit,
            oneiron::TokenAllocation::default(),
            default_selected_edges,
        );
        let selected_edges = retrieval.selected_edges.unwrap_or(defaults.selected_edges);
        builder = builder.retrieval_budget(oneiron::ContextPackRetrievalBudget::new(
            retrieval.claims.unwrap_or(defaults.claims),
            retrieval.turns.unwrap_or(defaults.turns),
            retrieval.summaries.unwrap_or(defaults.summaries),
            retrieval.facets.unwrap_or(defaults.facets),
            retrieval.other.unwrap_or(defaults.other),
            selected_edges,
        ));
    }
    Ok(builder)
}

fn run_context_pack_builder(
    vault: &oneiron::Vault,
    builder: oneiron::ContextPackBuilder<'_>,
    projection: oneiron::serialize::SerializeConfig,
    error_context: &'static str,
) -> Result<CoreContextPackResponse, ApiError> {
    let pack = builder
        .run_projected_json_with_telemetry(&projection)
        .map_err(|error| {
            tracing::error!(error = %error, "{error_context}");
            core_engine_error(error_context, error)
        })?;
    let run_id = pack.run_id;
    let pack = pack.value;
    let evidence = core_context_pack_evidence(vault, run_id)?;
    let evidence = core_context_pack_evidence_for_results(evidence, &pack.results);
    Ok(core_context_pack_response(pack, evidence))
}

fn run_core_query(
    vault: &oneiron::Vault,
    query: Option<&str>,
    vector: Option<&[f32]>,
    limit: usize,
) -> oneiron::Result<Vec<oneiron::ScoredEntity>> {
    match (query, vector) {
        (Some(query), Some(vector)) => vault.query().search(query, vector, None, limit).run(),
        (Some(query), None) => vault.search_text(query, limit),
        (None, Some(vector)) => vault.search_vector(vector, limit),
        (None, None) => Ok(Vec::new()),
    }
}

fn parse_short_ref_request(req: &CoreHydrateRequest) -> Result<(String, u8), ApiError> {
    if let Some(reference) = req.reference.as_deref() {
        return parse_short_ref(reference);
    }
    let Some(short_id) = req.short_id.as_deref() else {
        return Err(ApiError::bad_request(
            "ref or short_id/content_hash is required",
            Some("ref"),
        ));
    };
    let Some(content_hash) = req.content_hash.as_deref() else {
        return Err(ApiError::bad_request(
            "ref or short_id/content_hash is required",
            Some("content_hash"),
        ));
    };
    parse_short_ref_parts(short_id, content_hash)
}

fn parse_short_ref(reference: &str) -> Result<(String, u8), ApiError> {
    let Some((short_id, content_hash)) = reference.split_once(':') else {
        return Err(ApiError::bad_request(
            "ref must be in shortId:contentHashHex form",
            Some("ref"),
        ));
    };
    parse_short_ref_parts(short_id, content_hash)
}

fn parse_short_ref_parts(short_id: &str, content_hash: &str) -> Result<(String, u8), ApiError> {
    let short_id_bytes = short_id.as_bytes();
    if short_id_bytes.len() < 3
        || !short_id_bytes[0].is_ascii_lowercase()
        || !short_id_bytes[1].is_ascii_lowercase()
        || !short_id_bytes[2..].iter().all(|byte| byte.is_ascii_digit())
    {
        return Err(ApiError::bad_request(
            "short_id must be two lowercase letters followed by decimal digits",
            Some("short_id"),
        ));
    }
    if content_hash.len() != 2 || !content_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request(
            "content_hash must be exactly two hex digits",
            Some("content_hash"),
        ));
    }
    let content_hash = u8::from_str_radix(content_hash, 16)
        .map_err(|_| ApiError::bad_request("content_hash must be hex", Some("content_hash")))?;
    Ok((short_id.to_owned(), content_hash))
}

fn field_profile_for_view(view: View) -> oneiron::FieldProfile {
    match view {
        View::Summary => oneiron::FieldProfile::Minimal,
        View::Standard => oneiron::FieldProfile::Standard,
        View::Full => oneiron::FieldProfile::Full,
    }
}

fn context_pack_json_projection_config(
    view: View,
    budget: Option<&ContextPackBudgetControls>,
    top_level_max_item_tokens: usize,
) -> oneiron::serialize::SerializeConfig {
    oneiron::serialize::SerializeConfig {
        format: oneiron::PackFormat::Json,
        profile: field_profile_for_view(view),
        budget: 0,
        allocation: oneiron::TokenAllocation::default(),
        include_stats: false,
        merge_neighbors: false,
        max_field_chars: budget
            .and_then(|budget| budget.max_field_chars)
            .unwrap_or(oneiron::context_pack::DEFAULT_MAX_FIELD_CHARS),
        max_item_tokens: budget
            .and_then(|budget| budget.max_item_tokens)
            .unwrap_or(top_level_max_item_tokens),
    }
}

fn core_context_pack_evidence_for_results(
    mut evidence: CoreContextPackEvidence,
    results: &[oneiron::ContextEntity],
) -> CoreContextPackEvidence {
    let result_ids: BTreeSet<String> = results.iter().map(|entity| entity.id.to_hex()).collect();
    evidence
        .result_ids
        .retain(|result_id| result_ids.contains(result_id));
    evidence
        .scores
        .retain(|score| result_ids.contains(&score.result_id));
    evidence
}

fn core_context_pack_response(
    pack: oneiron::ContextPack,
    evidence: CoreContextPackEvidence,
) -> CoreContextPackResponse {
    let state = core_context_pack_state(pack.empty.as_ref());
    CoreContextPackResponse {
        results: pack.results.into_iter().map(core_context_entity).collect(),
        neighbors: pack
            .neighbors
            .into_iter()
            .map(core_context_entity)
            .collect(),
        stats: core_context_pack_stats(pack.stats),
        state,
        evidence,
        empty: pack
            .empty
            .map(|empty| serde_json::to_value(empty).expect("EmptyContext serializes")),
    }
}

fn core_context_entity(entity: oneiron::ContextEntity) -> CoreContextEntity {
    CoreContextEntity {
        id: entity.id.to_hex(),
        short_id: entity.short_id,
        content_hash: format!("{:02x}", entity.content_hash),
        entity_type: entity.entity_type,
        score: entity.score,
        fields: entity.fields.map(BTreeMap::from_iter),
        edges: entity
            .edges
            .map(|edges| edges.into_iter().map(core_context_edge).collect()),
        vector: entity.vector,
    }
}

fn core_context_edge(edge: oneiron::EdgeInfo) -> CoreContextEdge {
    CoreContextEdge {
        kind: edge.kind as u8,
        target: edge.target.to_hex(),
        target_short_id: edge.target_short_id,
        weight: edge.weight,
        created_at: edge.created_at,
        vad: edge.vad.map(Into::into),
    }
}

fn core_context_pack_stats(stats: oneiron::PackStats) -> CoreContextPackStats {
    CoreContextPackStats {
        candidates_considered: stats.candidates_considered,
        signals_used: stats
            .signals_used
            .into_iter()
            .map(|signal| signal_name(signal).to_owned())
            .collect(),
        query_time_us: stats.query_time_us,
        entities_hydrated: stats.entities_hydrated,
        neighbors_hydrated: stats.neighbors_hydrated,
        cosine_ghosts_dampened: stats.cosine_ghosts_dampened,
        claims_suppressed: stats.claims_suppressed,
        items_truncated: CoreContextPackItemAccounting {
            count: stats.items_truncated.count,
            reason: stats.items_truncated.reason.as_str().to_owned(),
        },
        items_dropped: CoreContextPackItemAccounting {
            count: stats.items_dropped.count,
            reason: stats.items_dropped.reason.as_str().to_owned(),
        },
    }
}

fn core_context_pack_state(empty: Option<&oneiron::EmptyContext>) -> CoreContextPackState {
    let Some(empty) = empty else {
        return CoreContextPackState {
            kind: CoreContextPackStateKind::Ok,
            reason: None,
            total_in_scope: None,
            hint: None,
        };
    };
    CoreContextPackState {
        kind: match empty.reason {
            oneiron::EmptyReason::BelowThreshold => CoreContextPackStateKind::LowConfidence,
            oneiron::EmptyReason::FilterMatchedNone
            | oneiron::EmptyReason::NoData
            | oneiron::EmptyReason::AllActivated => CoreContextPackStateKind::MissingData,
        },
        reason: Some(core_context_pack_state_reason(empty.reason)),
        total_in_scope: Some(empty.total_in_scope),
        hint: Some(empty.hint.clone()),
    }
}

fn core_context_pack_state_reason(reason: oneiron::EmptyReason) -> CoreContextPackStateReason {
    match reason {
        oneiron::EmptyReason::FilterMatchedNone => CoreContextPackStateReason::FilterMatchedNone,
        oneiron::EmptyReason::NoData => CoreContextPackStateReason::NoData,
        oneiron::EmptyReason::AllActivated => CoreContextPackStateReason::AllActivated,
        oneiron::EmptyReason::BelowThreshold => CoreContextPackStateReason::BelowThreshold,
    }
}

fn core_context_pack_evidence(
    vault: &oneiron::Vault,
    run_id: Option<oneiron::RetrievalRunId>,
) -> Result<CoreContextPackEvidence, ApiError> {
    let Some(run_id) = run_id else {
        return Ok(CoreContextPackEvidence {
            telemetry_persisted: false,
            retrieval_run_id: None,
            result_ids: Vec::new(),
            scores: Vec::new(),
        });
    };
    let Some(record) = vault.retrieval_run(run_id).map_err(|error| {
        tracing::error!(error = %error, "context-pack telemetry lookup failed");
        core_engine_error("context-pack telemetry lookup failed", error)
    })?
    else {
        return Ok(CoreContextPackEvidence {
            telemetry_persisted: false,
            retrieval_run_id: None,
            result_ids: Vec::new(),
            scores: Vec::new(),
        });
    };
    Ok(CoreContextPackEvidence {
        telemetry_persisted: true,
        retrieval_run_id: Some(record.run_id.to_hex()),
        result_ids: record.result_ids.iter().map(|id| hex_bytes(id)).collect(),
        scores: record
            .score_breakdown
            .into_iter()
            .map(core_context_pack_score_evidence)
            .collect(),
    })
}

fn core_context_pack_score_evidence(
    score: oneiron::RetrievalScoreBreakdown,
) -> CoreContextPackScoreEvidence {
    CoreContextPackScoreEvidence {
        result_id: hex_bytes(&score.result_id),
        final_rank: score.final_rank,
        final_score: score.final_score,
        components: score
            .components
            .into_iter()
            .map(core_context_pack_score_component)
            .collect(),
    }
}

fn core_context_pack_score_component(
    component: oneiron::RetrievalScoreComponent,
) -> CoreContextPackScoreComponent {
    CoreContextPackScoreComponent {
        signal: retrieval_signal_name(component.signal).to_owned(),
        rank: component.rank,
        score: component.score,
    }
}

fn signal_name(signal: oneiron::Signal) -> &'static str {
    match signal {
        oneiron::Signal::Vector => "vector",
        oneiron::Signal::Text => "text",
        oneiron::Signal::Phonetic => "phonetic",
        oneiron::Signal::Temporal => "temporal",
        oneiron::Signal::Ppr => "ppr",
        _ => "unknown",
    }
}

fn retrieval_signal_name(signal: oneiron::RetrievalSignal) -> &'static str {
    match signal {
        oneiron::RetrievalSignal::Vector => "vector",
        oneiron::RetrievalSignal::Text => "text",
        oneiron::RetrievalSignal::Phonetic => "phonetic",
        oneiron::RetrievalSignal::Temporal => "temporal",
        oneiron::RetrievalSignal::Ppr => "ppr",
    }
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

fn core_list_limit(limit: usize) -> usize {
    limit.min(CORE_MAX_LIST_LIMIT)
}

fn core_list_entities_by_type(
    vault: &oneiron::Vault,
    entity_type: u8,
    params: CoreListQuery,
) -> Result<Json<SearchResponse>, EnvelopedApiError> {
    let view = params.view.unwrap_or(View::Summary);
    let limit = core_list_limit(params.limit);
    let after = params
        .after
        .as_deref()
        .map(|after| parse_entity_id_param(after, "after"))
        .transpose()?;
    let (ids, next_cursor) = collect_live_entity_page(vault, after, limit, |after, limit| {
        vault
            .entities_by_type_page(entity_type, after, limit)
            .map_err(|error| {
                tracing::error!(error = %error, entity_type, "core list failed");
                core_engine_error("core list failed", error).into()
            })
    })?;
    let items = project_entity_ids(vault, ids, view)?;
    let meta = match params.count_mode {
        CountMode::None => ResponseMeta::none(),
        CountMode::Estimate => ResponseMeta::estimate(items.len() as u64),
        CountMode::Exact => {
            let total = count_live_entities_by_type(vault, entity_type)?;
            ResponseMeta::new(total, CountMode::Exact)
        }
    };
    Ok(Json(PaginatedResponse::new(items, next_cursor, meta)))
}

fn core_list_conversation_turns(
    vault: &oneiron::Vault,
    conversation: &oneiron::EntityId,
    params: CoreListQuery,
) -> Result<Json<SearchResponse>, EnvelopedApiError> {
    let view = params.view.unwrap_or(View::Summary);
    let limit = core_list_limit(params.limit);
    let after = params
        .after
        .as_deref()
        .map(|after| parse_entity_id_param(after, "after"))
        .transpose()?;
    let (ids, next_cursor) = collect_live_entity_page(vault, after, limit, |after, limit| {
        vault
            .sources_page(
                conversation,
                EdgeKind::ChildOf,
                Some(ENTITY_TYPE_TURN),
                after,
                limit,
            )
            .map_err(|error| {
                tracing::error!(error = %error, conversation = %conversation.to_hex(), "core conversation turns failed");
                core_engine_error("core conversation turns failed", error).into()
            })
    })?;
    let items = project_entity_ids(vault, ids, view)?;
    let meta = match params.count_mode {
        CountMode::None => ResponseMeta::none(),
        CountMode::Estimate => ResponseMeta::estimate(items.len() as u64),
        CountMode::Exact => ResponseMeta::new(
            count_live_conversation_turns(vault, conversation)?,
            CountMode::Exact,
        ),
    };
    Ok(Json(PaginatedResponse::new(items, next_cursor, meta)))
}

fn collect_live_entity_page<F>(
    vault: &oneiron::Vault,
    after: Option<oneiron::EntityId>,
    limit: usize,
    mut fetch: F,
) -> Result<(Vec<oneiron::EntityId>, Option<String>), EnvelopedApiError>
where
    F: FnMut(
        Option<&oneiron::EntityId>,
        usize,
    ) -> Result<Vec<oneiron::EntityId>, EnvelopedApiError>,
{
    if limit == 0 {
        return Ok((Vec::new(), None));
    }

    let mut cursor = after;
    let mut ids = Vec::with_capacity(limit);
    let mut next_cursor = None;

    while next_cursor.is_none() {
        let remaining = limit.saturating_sub(ids.len());
        let fetch_limit = if remaining == 0 {
            1
        } else {
            remaining.saturating_add(1)
        };
        let fetched = fetch(cursor.as_ref(), fetch_limit)?;
        if fetched.is_empty() {
            break;
        }

        let fetched_len = fetched.len();
        for id in fetched {
            cursor = Some(id);
            if is_deleted_shell_for_core_list(vault, &id)? {
                continue;
            }
            if ids.len() < limit {
                ids.push(id);
            } else {
                next_cursor = ids.last().map(oneiron::EntityId::to_hex);
                break;
            }
        }

        if fetched_len < fetch_limit {
            break;
        }
    }

    Ok((ids, next_cursor))
}

fn count_live_entities_by_type(
    vault: &oneiron::Vault,
    entity_type: u8,
) -> Result<u64, EnvelopedApiError> {
    let mut after = None;
    let mut total = 0_u64;
    loop {
        let ids = vault
            .entities_by_type_page(entity_type, after.as_ref(), CORE_MAX_LIST_LIMIT)
            .map_err(|error| {
                tracing::error!(error = %error, entity_type, "core list count failed");
                core_engine_error("core list count failed", error)
            })?;
        if ids.is_empty() {
            break;
        }
        for id in &ids {
            if !is_deleted_shell_for_core_list(vault, id)? {
                total = total.saturating_add(1);
            }
        }
        after = ids.last().copied();
        if ids.len() < CORE_MAX_LIST_LIMIT {
            break;
        }
    }
    Ok(total)
}

fn count_live_conversation_turns(
    vault: &oneiron::Vault,
    conversation: &oneiron::EntityId,
) -> Result<u64, EnvelopedApiError> {
    let mut after = None;
    let mut total = 0_u64;
    loop {
        let ids = vault
            .sources_page(
                conversation,
                EdgeKind::ChildOf,
                Some(ENTITY_TYPE_TURN),
                after.as_ref(),
                CORE_MAX_LIST_LIMIT,
            )
            .map_err(|error| {
                tracing::error!(error = %error, conversation = %conversation.to_hex(), "core conversation turns count failed");
                core_engine_error("core conversation turns count failed", error)
            })?;
        if ids.is_empty() {
            break;
        }
        for id in &ids {
            if !is_deleted_shell_for_core_list(vault, id)? {
                total = total.saturating_add(1);
            }
        }
        after = ids.last().copied();
        if ids.len() < CORE_MAX_LIST_LIMIT {
            break;
        }
    }
    Ok(total)
}

fn is_deleted_shell_for_core_list(
    vault: &oneiron::Vault,
    id: &oneiron::EntityId,
) -> Result<bool, ApiError> {
    vault.is_deleted_shell(id).map_err(|error| {
        tracing::error!(error = %error, id = %id.to_hex(), "core deleted-shell check failed");
        core_engine_error("core deleted-shell check failed", error)
    })
}

fn project_entity_ids(
    vault: &oneiron::Vault,
    ids: Vec<oneiron::EntityId>,
    view: View,
) -> Result<Vec<Value>, ApiError> {
    let mut items = Vec::with_capacity(ids.len());
    for id in ids {
        if is_deleted_shell_for_core_list(vault, &id)? {
            continue;
        }
        if let Some(item) = projection::project_entity(vault, &id, view).map_err(|error| {
            tracing::error!(error = %error, id = %id.to_hex(), "core projection failed");
            core_engine_error("core projection failed", error)
        })? {
            items.push(item);
        }
    }
    Ok(items)
}

struct CoreEntityWriteInput<'a> {
    id: Option<&'a str>,
    entity_type: u8,
    occurred_start: Option<u64>,
    occurred_end: Option<u64>,
    learned_at: Option<u64>,
    body: &'a Value,
    text: Option<&'a [CoreTextField]>,
}

fn write_core_entity(
    vault: &oneiron::Vault,
    input: CoreEntityWriteInput<'_>,
) -> Result<Json<CoreEntityWriteResponse>, EnvelopedApiError> {
    let id = parse_optional_entity_id(input.id, "id")?;
    let timestamps =
        core_entity_timestamps(input.occurred_start, input.occurred_end, input.learned_at)?;
    let batch = stage_core_entity_put(
        vault.batch(),
        &id,
        input.entity_type,
        timestamps,
        input.body,
        input.text,
    )?;
    batch.commit().map_err(|error| {
        tracing::error!(error = %error, entity_type = input.entity_type, "core entity create failed");
        core_engine_error("core entity create failed", error)
    })?;
    let item = projection::project_entity_parts(
        &id,
        input.entity_type,
        timestamps.learned_at,
        &encode_core_body(input.body)?,
        View::Full,
    );
    Ok(Json(CoreEntityWriteResponse {
        id: id.to_hex(),
        entity_type: input.entity_type,
        item,
    }))
}

fn project_core_entity(
    vault: &oneiron::Vault,
    id: &oneiron::EntityId,
    view: View,
) -> Result<Json<Value>, EnvelopedApiError> {
    let Some(item) = projection::project_entity(vault, id, view).map_err(|error| {
        tracing::error!(error = %error, id = %id.to_hex(), "core entity read failed");
        core_engine_error("core entity read failed", error)
    })?
    else {
        return Err(ApiError::not_found("entity", Some(&id.to_hex())).into());
    };
    Ok(Json(item))
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
        | ErrorKind::InvalidCodeArtifactBody
        | ErrorKind::InvalidCodebaseSnapshotBody
        | ErrorKind::InvalidCodeSymbolManifestBody
        | ErrorKind::MaintenanceKindNotWritable
        | ErrorKind::EntityTypeImmutable
        | ErrorKind::StructuralKindBandViolation
        | ErrorKind::StructuralKindCollision
        | ErrorKind::InvalidStructuralKindRegistration
        | ErrorKind::ClaimSelfSupersession
        | ErrorKind::ProvenanceClaimLifecycle => ApiError::bad_request(error.to_string(), None),
        ErrorKind::EntityNotFound | ErrorKind::EdgeNotFound => ApiError::not_found("entity", None),
        ErrorKind::CycleDetected | ErrorKind::ChildOfCardinality => {
            ApiError::invalid_state(Some("child_of_constraint"))
        }
        ErrorKind::ClaimAlreadyClosed | ErrorKind::ProvenanceClaimAlreadyClosed => {
            ApiError::invalid_state(Some("memory_lifecycle_closed"))
        }
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

/// Valence/arousal/dominance annotation payload.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "valence": 0.25,
    "arousal": 0.5,
    "dominance": 0.75
}))]
struct VadPayload {
    /// Valence in the same range as edge VAD: `[-1, 1]`.
    #[schema(example = 0.25)]
    valence: f32,
    /// Arousal in the same range as edge VAD: `[0, 1]`.
    #[schema(example = 0.5)]
    arousal: f32,
    /// Dominance in the same range as edge VAD: `[0, 1]`.
    #[schema(example = 0.75)]
    dominance: f32,
}

impl VadPayload {
    fn into_vad(self) -> Result<Vad, ApiError> {
        let vad = Vad {
            valence: self.valence,
            arousal: self.arousal,
            dominance: self.dominance,
        };
        vad.validate()
            .map_err(|error| ApiError::bad_request(error.to_string(), Some("vad")))?;
        Ok(vad)
    }
}

impl From<Vad> for VadPayload {
    fn from(vad: Vad) -> Self {
        Self {
            valence: vad.valence,
            arousal: vad.arousal,
            dominance: vad.dominance,
        }
    }
}

/// Source that produced a turn/message VAD annotation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum TurnVadAnnotationSource {
    /// VAD inferred by a model or upstream inference service.
    ModelInference,
    /// VAD reported directly by the user.
    UserSelfReport,
}

impl From<TurnVadAnnotationSource> for VadAnnotationSource {
    fn from(source: TurnVadAnnotationSource) -> Self {
        match source {
            TurnVadAnnotationSource::ModelInference => Self::ModelInference,
            TurnVadAnnotationSource::UserSelfReport => Self::UserSelfReport,
        }
    }
}

impl From<VadAnnotationSource> for TurnVadAnnotationSource {
    fn from(source: VadAnnotationSource) -> Self {
        match source {
            VadAnnotationSource::ModelInference => Self::ModelInference,
            VadAnnotationSource::UserSelfReport => Self::UserSelfReport,
        }
    }
}

/// Request body for writing VAD metadata to a turn or one message in a turn.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "turn_id": "0123456789abcdef0123456789abcdef",
    "source": "model_inference",
    "vad": {
        "valence": 0.25,
        "arousal": 0.5,
        "dominance": 0.75
    },
    "annotated_at": 1782357635_u64
}))]
struct TurnVadAnnotateRequest {
    /// Hex-encoded TURN entity id anchoring the annotation request.
    #[serde(rename = "turn_id", alias = "turnId")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    turn_id: String,
    /// Optional hex-encoded MESSAGE entity id; omit to annotate the turn itself.
    #[serde(default, rename = "message_id", alias = "messageId")]
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    message_id: Option<String>,
    /// VAD values to persist.
    vad: VadPayload,
    /// Source that produced the VAD values.
    source: TurnVadAnnotationSource,
    /// Unix seconds timestamp for the annotation. Defaults to server time.
    #[serde(default, rename = "annotated_at", alias = "annotatedAt")]
    #[schema(example = 1782357635_u64)]
    annotated_at: Option<u64>,
}

/// Query parameters for reading VAD metadata from a turn or message.
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
struct TurnVadAnnotateQuery {
    /// Hex-encoded TURN entity id anchoring the annotation lookup.
    #[serde(rename = "turn_id", alias = "turnId")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    #[param(example = "0123456789abcdef0123456789abcdef")]
    turn_id: String,
    /// Optional hex-encoded MESSAGE entity id; omit to read the turn annotation.
    #[serde(default, rename = "message_id", alias = "messageId")]
    #[schema(example = "fedcba9876543210fedcba9876543210")]
    #[param(example = "fedcba9876543210fedcba9876543210")]
    message_id: Option<String>,
}

/// Persisted VAD metadata returned by the turn annotation endpoint.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "turn_id": "0123456789abcdef0123456789abcdef",
    "message_id": null,
    "source": "model_inference",
    "vad": {
        "valence": 0.25,
        "arousal": 0.5,
        "dominance": 0.75
    },
    "annotated_at": 1782357635_u64
}))]
struct TurnVadAnnotateResponse {
    /// Hex-encoded TURN entity id anchoring the annotation.
    #[serde(rename = "turn_id")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    turn_id: String,
    /// Hex-encoded MESSAGE entity id when the annotation targets a message.
    #[serde(rename = "message_id")]
    #[schema(nullable = true, example = "fedcba9876543210fedcba9876543210")]
    message_id: Option<String>,
    /// Persisted VAD values.
    vad: VadPayload,
    /// Persisted source for the VAD values.
    source: TurnVadAnnotationSource,
    /// Unix seconds timestamp persisted with the annotation.
    #[serde(rename = "annotated_at")]
    #[schema(example = 1782357635_u64)]
    annotated_at: u64,
}

impl TurnVadAnnotateResponse {
    fn new(turn_id: &str, message_id: Option<&str>, annotation: VadAnnotation) -> Self {
        Self {
            turn_id: turn_id.to_owned(),
            message_id: message_id.map(str::to_owned),
            vad: annotation.vad.into(),
            source: annotation.source.into(),
            annotated_at: annotation.annotated_at,
        }
    }
}

/// Write VAD metadata for a turn or one message in a turn.
#[utoipa::path(
    post,
    path = "/v1/core/turns/annotate",
    request_body(
        content = TurnVadAnnotateRequest,
        description = "VAD metadata annotation for a turn, or for a message when `message_id` is supplied.",
        content_type = "application/json"
    ),
    responses(
        (
            status = 200,
            description = "VAD annotation persisted and returned.",
            body = TurnVadAnnotateResponse,
            content_type = "application/json"
        ),
        (
            status = 400,
            description = "Malformed id, invalid target type, message outside turn, or VAD outside the contract ranges.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid scoped bearer token, or missing/invalid legacy `x-oneiron-secret` header.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 403,
            description = "Bearer token is valid but lacks the required `core:write` scope.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 409,
            description = "Active Gate policy rejected the VAD annotation write; response uses INVALID_STATE with Gate outcome and reason codes.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 404,
            description = "Turn or message entity was not found.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "VAD annotation persistence failed.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        )
    )
)]
async fn annotate_turn_vad(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<TurnVadAnnotateRequest>, JsonRejection>,
) -> Result<Json<TurnVadAnnotateResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let req = json_payload(payload)?;
    let turn_id = parse_entity_id_param(&req.turn_id, "turn_id")?;
    require_entity_type(&server, &turn_id, ENTITY_TYPE_TURN, "turn")?;

    let vad = req.vad.into_vad()?;
    let annotated_at = req.annotated_at.unwrap_or_else(unix_seconds_now);
    let annotation = VadAnnotation::new(vad, req.source.into(), annotated_at)
        .map_err(vad_annotation_core_error)?;

    let stored = if let Some(message_id_hex) = &req.message_id {
        let message_id = parse_entity_id_param(message_id_hex, "message_id")?;
        require_entity_type(&server, &message_id, ENTITY_TYPE_MESSAGE, "message")?;
        require_message_in_turn(&server, &turn_id, &message_id)?;
        server
            .vault
            .annotate_message_vad(&message_id, annotation)
            .map_err(vad_annotation_core_error)?
    } else {
        server
            .vault
            .annotate_turn_vad(&turn_id, annotation)
            .map_err(vad_annotation_core_error)?
    };

    Ok(Json(TurnVadAnnotateResponse::new(
        &req.turn_id,
        req.message_id.as_deref(),
        stored,
    )))
}

/// Read VAD metadata for a turn or one message in a turn.
#[utoipa::path(
    get,
    path = "/v1/core/turns/annotate",
    params(TurnVadAnnotateQuery),
    responses(
        (
            status = 200,
            description = "Persisted VAD annotation for the requested turn or message.",
            body = TurnVadAnnotateResponse,
            content_type = "application/json"
        ),
        (
            status = 400,
            description = "Malformed id, invalid target type, or message outside turn.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid scoped bearer token, or missing/invalid legacy `x-oneiron-secret` header.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 403,
            description = "Bearer token is valid but lacks the required `core:read` scope.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 404,
            description = "Turn/message entity or VAD annotation was not found.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "VAD annotation read failed.",
            body = ApiErrorEnvelope,
            content_type = "application/json"
        )
    )
)]
async fn read_turn_vad_annotation(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<TurnVadAnnotateQuery>, QueryRejection>,
) -> Result<Json<TurnVadAnnotateResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let params = query_params(query)?;
    let turn_id = parse_entity_id_param(&params.turn_id, "turn_id")?;
    require_entity_type(&server, &turn_id, ENTITY_TYPE_TURN, "turn")?;

    let annotation = if let Some(message_id_hex) = &params.message_id {
        let message_id = parse_entity_id_param(message_id_hex, "message_id")?;
        require_entity_type(&server, &message_id, ENTITY_TYPE_MESSAGE, "message")?;
        require_message_in_turn(&server, &turn_id, &message_id)?;
        server
            .vault
            .get_message_vad_annotation(&message_id)
            .map_err(vad_annotation_core_error)?
    } else {
        server
            .vault
            .get_turn_vad_annotation(&turn_id)
            .map_err(vad_annotation_core_error)?
    };

    let Some(annotation) = annotation else {
        let id = params.message_id.as_deref().unwrap_or(&params.turn_id);
        return Err(ApiError::not_found("vad_annotation", Some(id)).into());
    };

    Ok(Json(TurnVadAnnotateResponse::new(
        &params.turn_id,
        params.message_id.as_deref(),
        annotation,
    )))
}

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

fn require_message_in_turn(
    server: &SyncServer,
    turn_id: &oneiron::EntityId,
    message_id: &oneiron::EntityId,
) -> Result<(), ApiError> {
    match server
        .vault
        .edge_exists(message_id, EdgeKind::ChildOf, turn_id)
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(ApiError::bad_request(
            "message_id does not belong to turn_id",
            Some("message_id"),
        )),
        Err(error) => {
            tracing::error!(error = %error, "message turn relationship lookup failed");
            Err(ApiError::internal_server_error(
                "message turn relationship lookup failed",
            ))
        }
    }
}

fn vad_annotation_core_error(error: oneiron::Error) -> ApiError {
    match error {
        oneiron::Error::GateWriteRejected {
            outcome,
            reason_codes,
        } => {
            let reason_codes = reason_codes.join(",");
            ApiError::new(
                format!(
                    "VAD annotation rejected by Gate: outcome={outcome}, reasons={reason_codes}"
                ),
                ApiErrorDetails::InvalidState {
                    state: Some(format!("gate_write_rejected:{outcome}:{reason_codes}")),
                },
                [
                    "Route the annotation through policy review or adjust the active Gate policy before retrying.",
                ],
            )
        }
        error => match error.kind() {
            ErrorKind::InvalidVad => ApiError::bad_request(error.to_string(), Some("vad")),
            ErrorKind::InvalidEntityType => {
                ApiError::bad_request(error.to_string(), Some("entity"))
            }
            ErrorKind::EntityNotFound => ApiError::not_found("entity", None),
            _ => {
                tracing::error!(error = %error, "VAD annotation operation failed");
                ApiError::internal_server_error("VAD annotation operation failed")
            }
        },
    }
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

// ─── Lease revocation (ONE-1140, OD-8) ────────────────────────────────────────

/// Request body for revoking one device lease binding.
#[derive(Deserialize, ToSchema)]
#[schema(example = json!({
    "client_id": "0000000000000042"
}))]
struct LeaseRevokeRequest {
    /// Device lease-binding id to revoke for lost-device or stolen-device recovery. The value is the binding's registry key encoded as 16 lowercase hex chars (`{:016x}`).
    #[schema(example = "0000000000000042")]
    client_id: String,
}

/// Result of a lease revocation request.
#[derive(Serialize, ToSchema)]
#[schema(example = json!({
    "revoked": true
}))]
struct LeaseRevokeResponse {
    /// `true` when an active binding was found and marked revoked; `false` when the id was well-formed but no binding existed.
    #[schema(example = true)]
    revoked: bool,
}

/// Revokes a device-lease binding (owner recovery, OD-8 — terminal for the
/// binding; auth = Phase-1 shared secret, same as every API route). The
/// registry change is broadcast to all live connections so replica `ls:`
/// mirrors converge without a reconnect.
#[utoipa::path(
    post,
    path = "/api/lease/revoke",
    request_body(
        content = LeaseRevokeRequest,
        description = "Lease binding to revoke for owner recovery.",
        content_type = "application/json"
    ),
    responses(
        (
            status = 200,
            description = "Lease revocation completed or found no matching binding.",
            body = LeaseRevokeResponse,
            content_type = "application/json",
            example = json!({
                "revoked": true
            })
        ),
        (
            status = 400,
            description = "`client_id` is not exactly 16 lowercase hex characters.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid `x-oneiron-secret` header.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Lease revocation failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
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

/// Request body for assembling a context pack from text and/or vector seeds.
#[derive(Deserialize, ToSchema)]
#[schema(example = json!({
    "query": "recent decisions about project alpha",
    "query_vector": [0.12, -0.04, 0.98],
    "limit": 10,
    "depth": { "edge_hop": 1, "max_neighbors": 50 },
    "policy": { "hydrate": true, "include_edges": true, "view": "full" },
    "time": { "since": 1782357600 },
    "budget": { "max_item_tokens": 512 }
}))]
struct ContextPackRequest {
    /// Optional text retrieval seed for context-pack assembly; omit when the caller only has an embedding vector.
    #[serde(default)]
    #[schema(example = "recent decisions about project alpha")]
    query: Option<String>,
    /// Optional embedding vector retrieval seed; omit when the caller only has text.
    #[serde(default, rename = "query_vector", alias = "queryVector")]
    #[schema(example = json!([0.12, -0.04, 0.98]))]
    query_vector: Option<Vec<f32>>,
    /// Maximum number of candidate entities to retrieve for the pack. Defaults to `10` when omitted.
    #[serde(default = "default_limit")]
    #[schema(default = default_limit, example = 10)]
    limit: usize,
    /// Per-item token cap for context-pack serialization; 0 disables it.
    #[serde(default, rename = "maxItemTokens", alias = "max_item_tokens")]
    max_item_tokens: usize,
    /// Whether to include hydrated fields. Defaults to true.
    #[serde(default = "default_true")]
    #[schema(default = default_true, example = true)]
    hydrate: bool,
    /// Whether to include edge records in hydrated entities.
    #[serde(default, rename = "include_edges", alias = "includeEdges")]
    #[schema(example = true)]
    include_edges: bool,
    /// Edge expansion depth for neighbor hydration.
    #[serde(default, rename = "edge_hop", alias = "edgeHop")]
    #[schema(example = 1)]
    edge_hop: u32,
    /// Maximum neighbors to hydrate during edge expansion.
    #[serde(
        default = "default_context_neighbors",
        rename = "max_neighbors",
        alias = "maxNeighbors"
    )]
    #[schema(default = default_context_neighbors, example = 50)]
    max_neighbors: usize,
    /// Whether to include stored vectors when present.
    #[serde(default, rename = "include_vectors", alias = "includeVectors")]
    #[schema(example = false)]
    include_vectors: bool,
    /// Field profile for hydrated fields. Defaults to standard.
    #[serde(default)]
    #[schema(example = "standard")]
    view: Option<View>,
    /// Optional nested depth controls. Overrides top-level edge_hop/max_neighbors when set.
    #[serde(default)]
    depth: Option<ContextPackDepthControls>,
    /// Optional nested ranking/projection policy controls.
    #[serde(default)]
    policy: Option<ContextPackPolicyControls>,
    /// Optional time-window filters.
    #[serde(default)]
    time: Option<ContextPackTimeControls>,
    /// Optional retrieval and serialization budget controls.
    #[serde(default)]
    budget: Option<ContextPackBudgetControls>,
}

/// Context pack assembly.
#[utoipa::path(
    post,
    path = "/api/context-pack",
    request_body(
        content = ContextPackRequest,
        description = "Text and/or vector seed plus retrieval limits for context-pack assembly.",
        content_type = "application/json"
    ),
    responses(
        (
            status = 200,
            description = "Context pack assembled.",
            body = CoreContextPackResponse,
            content_type = "application/json",
            example = json!({
                "results": [],
                "neighbors": [],
                "stats": {
                    "candidates_considered": 0,
                    "signals_used": ["text"],
                    "query_time_us": 1000,
                    "entities_hydrated": 0,
                    "neighbors_hydrated": 0,
                    "cosine_ghosts_dampened": 0,
                    "claims_suppressed": 0,
                    "items_truncated": { "count": 0, "reason": "item_budget" },
                    "items_dropped": { "count": 0, "reason": "token_budget" }
                },
                "state": { "kind": "missing_data", "reason": "no_data", "total_in_scope": 0 },
                "evidence": { "telemetry_persisted": true, "retrieval_run_id": "018f0000000000000000000000000000", "result_ids": [], "scores": [] }
            })
        ),
        (
            status = 400,
            description = "Malformed context-pack request or controls.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid `x-oneiron-secret` header.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
async fn context_pack(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ContextPackRequest>, JsonRejection>,
) -> Result<Json<CoreContextPackResponse>, ApiError> {
    check_api_auth(&headers, &server.config)?;
    let req = json_payload(payload)?;
    let query = non_empty_query(req.query.as_deref());
    validate_core_query_seeds(query, req.query_vector.as_deref())?;
    let (edge_hop, edge_hop_field, max_neighbors, max_neighbors_field) =
        resolved_context_pack_depth(req.depth.as_ref(), req.edge_hop, req.max_neighbors);
    validate_context_pack_depth(edge_hop, edge_hop_field, max_neighbors, max_neighbors_field)?;
    let hydrate = req
        .policy
        .as_ref()
        .and_then(|policy| policy.hydrate)
        .unwrap_or(req.hydrate);
    let include_edges = req
        .policy
        .as_ref()
        .and_then(|policy| policy.include_edges)
        .unwrap_or(req.include_edges);
    let include_vectors = req
        .policy
        .as_ref()
        .and_then(|policy| policy.include_vectors)
        .unwrap_or(req.include_vectors);
    let view = req
        .policy
        .as_ref()
        .and_then(|policy| policy.view)
        .or(req.view)
        .unwrap_or(View::Standard);
    let projection =
        context_pack_json_projection_config(view, req.budget.as_ref(), req.max_item_tokens);

    let mut builder = server
        .vault
        .context_pack()
        .limit(req.limit)
        .hydrate(hydrate)
        .include_edges(include_edges)
        .edge_hop(edge_hop)
        .max_neighbors(max_neighbors)
        .include_vectors(include_vectors)
        .field_profile(projection.profile);
    if let Some(query) = query {
        builder = builder.search_text(query, req.limit);
    }
    if let Some(vector) = req.query_vector.as_deref() {
        builder = builder.search_vector(vector, req.limit);
    }
    builder = apply_context_pack_policy(builder, req.policy.as_ref())?;
    builder = apply_context_pack_time(builder, req.time.as_ref())?;
    builder = apply_context_pack_budget(
        builder,
        req.budget.as_ref(),
        req.max_item_tokens,
        req.limit,
        max_neighbors,
    )?;

    Ok(Json(run_context_pack_builder(
        &server.vault,
        builder,
        projection,
        "context-pack failed",
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header::AUTHORIZATION, header::CONTENT_TYPE};
    use serde_json::Map;
    use serde_json::Value;
    use tower::ServiceExt;

    const V1_CORE_OPENAPI_CONTRACT_SNAPSHOT: &str =
        include_str!("../tests/fixtures/v1_core_openapi_contract.snapshot.json");
    const V1_CORE_OPENAPI_CONTRACT_SNAPSHOT_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/v1_core_openapi_contract.snapshot.json"
    );
    const V1_CORE_SUCCESS_CONTRACT_SNAPSHOT: &str =
        include_str!("../tests/fixtures/v1_core_success_contract.snapshot.json");
    const V1_CORE_SUCCESS_CONTRACT_SNAPSHOT_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/v1_core_success_contract.snapshot.json"
    );
    const V1_CORE_ERROR_CONTRACT_SNAPSHOT: &str =
        include_str!("../tests/fixtures/v1_core_error_contract.snapshot.json");
    const V1_CORE_ERROR_CONTRACT_SNAPSHOT_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/v1_core_error_contract.snapshot.json"
    );
    const V1_CORE_OPENAPI_CONTRACT_OPERATIONS: &[(&str, &str)] = &[
        ("/v1/core/batch", "post"),
        ("/v1/core/query", "post"),
        ("/v1/core/context-pack", "post"),
        ("/v1/core/hydrate", "post"),
        ("/v1/core/batch/shortId/hydrate", "post"),
        ("/v1/core/conversations", "get"),
        ("/v1/core/conversations", "post"),
        ("/v1/core/conversations/{conversation_id}/turns", "get"),
        ("/v1/core/conversations/{conversation_id}/turns", "post"),
        ("/v1/core/turns/{turn_id}", "get"),
        ("/v1/core/turns/annotate", "get"),
        ("/v1/core/turns/annotate", "post"),
    ];
    const V1_CORE_OPENAPI_CONTRACT_SCHEMA_NAMES: &[&str] = &[
        "ApiError",
        "ApiErrorDetails",
        "ApiErrorEnvelope",
        "ErrorCode",
        "CoreBatchEntityInput",
        "CoreBatchEntityResult",
        "CoreBatchRequest",
        "CoreBatchResponse",
        "CoreContextEdge",
        "CoreContextEntity",
        "CoreContextPackItemAccounting",
        "ContextPackBudgetControls",
        "ContextPackDepthControls",
        "ContextPackPolicyControls",
        "ContextPackRetrievalBudgetControls",
        "ContextPackTimeControls",
        "CoreContextPackEvidence",
        "CoreContextPackRequest",
        "CoreContextPackResponse",
        "CoreContextPackScoreComponent",
        "CoreContextPackScoreEvidence",
        "CoreContextPackState",
        "CoreContextPackStateKind",
        "CoreContextPackStateReason",
        "CoreContextPackStats",
        "CoreCreateEntityRequest",
        "CoreCreateTurnRequest",
        "CoreEntityWriteResponse",
        "CoreBatchShortIdHydrateItem",
        "CoreBatchShortIdHydrateRequest",
        "CoreBatchShortIdHydrateResponse",
        "CoreShortIdHydrateOutcome",
        "CoreHydrateDeletionMetadata",
        "CoreHydrateDeletionReason",
        "CoreHydrateDeletionSource",
        "CoreHydrateRequest",
        "CoreHydrateResponse",
        "CoreHydrateStatus",
        "CoreListQuery",
        "CoreMemoryOperationKind",
        "CoreMemoryTimelineRecord",
        "CoreMemoryTimelineRecordState",
        "CoreMemoryTimelineResponse",
        "CoreMemoryVerbDeleteOutcome",
        "CoreMemoryVerbDeleteReason",
        "CoreMemoryVerbRequest",
        "CoreMemoryVerbResponse",
        "CoreQueryRequest",
        "CoreShortIdHydrateError",
        "CoreShortIdHydrateErrorKind",
        "CoreTextField",
        "CountMode",
        "ResponseMeta",
        "TurnVadAnnotateQuery",
        "TurnVadAnnotateRequest",
        "TurnVadAnnotateResponse",
        "TurnVadAnnotationSource",
        "VadPayload",
        "View",
    ];

    #[test]
    fn search_response_drops_stale_hydrated_hits() {
        let dir = tempfile::tempdir().unwrap();
        let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap();
        let stale_hit = oneiron::ScoredEntity {
            id: oneiron::EntityId::now(),
            score: 0.75,
        };

        for view in [View::Summary, View::Full] {
            let response = search_response(&vault, vec![stale_hit], view, 10).unwrap();
            assert!(
                response.is_empty(),
                "{view:?} should skip missing search hits"
            );
        }
    }

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

    fn generated_spec() -> Value {
        openapi_document()
    }

    fn assert_non_empty_string(value: &Value, context: &str) {
        assert!(
            value.as_str().is_some_and(|s| !s.trim().is_empty()),
            "{context} must be a non-empty string, got {value:?}"
        );
    }

    fn test_server() -> (tempfile::TempDir, Arc<SyncServer>) {
        test_server_with_config(SyncServerConfig {
            allow_unauthenticated: true,
            ..Default::default()
        })
    }

    fn test_server_with_config(config: SyncServerConfig) -> (tempfile::TempDir, Arc<SyncServer>) {
        let dir = tempfile::tempdir().expect("temp vault dir");
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
        let server = Arc::new(SyncServer::new(vault, config).expect("sync server"));
        (dir, server)
    }

    fn test_server_with_usage_mode(usage_mode: UsageMode) -> (tempfile::TempDir, Arc<SyncServer>) {
        test_server_with_config(SyncServerConfig {
            allow_unauthenticated: true,
            usage_mode,
            ..Default::default()
        })
    }

    fn seeded_test_entity_id(counter: u128) -> oneiron::EntityId {
        let mut bytes = counter.to_be_bytes();
        bytes[0] = 0x7e;
        oneiron::EntityId::from_bytes(bytes).expect("seeded test id should be valid")
    }

    fn seed_active_claim(
        server: &SyncServer,
        id: oneiron::EntityId,
        subject: oneiron::EntityId,
        value: &str,
        learned_at: u64,
    ) {
        #[derive(serde::Serialize)]
        struct ClaimSeed<'a> {
            pred: &'a str,
            val: &'a str,
            conf: f32,
            #[serde(with = "serde_bytes")]
            subj: &'a [u8],
            appr: &'static str,
            life: &'static str,
        }

        let body = rmp_serde::to_vec_named(&ClaimSeed {
            pred: "profile.route_test",
            val: value,
            conf: 0.9,
            subj: subject.as_bytes(),
            appr: "auto",
            life: "active",
        })
        .expect("encode claim fixture");
        server
            .vault
            .put_entity(
                &id,
                oneiron::types::ENTITY_TYPE_CLAIM,
                oneiron::TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                &body,
            )
            .expect("seed active claim");
    }

    #[tokio::test]
    async fn health_runtime_summary_redacts_route_model_details_without_auth() {
        let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::LocalFree);
        runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
            RuntimeRole::Orchestrator,
            crate::runtime::RuntimeRoleTargetOverride::target(
                RuntimeProviderKind::Local,
                "sensitive-orchestrator-model",
            ),
        ));
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            runtime,
            ..Default::default()
        });

        let response = api_routes(server)
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("health response body");
        let body: Value = serde_json::from_slice(&body).expect("health JSON body");
        assert_eq!(body["runtime"]["mode"], Value::from("local_free"));
        assert_eq!(body["runtime"]["oneironSpendMetered"], Value::from(false));
        assert_eq!(body["runtime"]["state"], Value::from("available"));
        assert!(body["runtime"].get("routes").is_none());

        let runtime_json = body["runtime"].to_string();
        for redacted in [
            "sensitive-orchestrator-model",
            "orchestrator",
            "providerKind",
            "provenance",
        ] {
            assert!(
                !runtime_json.contains(redacted),
                "health runtime summary leaked {redacted}: {runtime_json}"
            );
        }
    }

    #[tokio::test]
    async fn runtime_status_uses_legacy_usage_mode_when_runtime_is_default() {
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            allow_unauthenticated: true,
            usage_mode: crate::usage::UsageMode::OneironCloud,
            runtime: crate::runtime::RuntimeConfig::default(),
            ..Default::default()
        });

        let response = api_routes(server.clone())
            .oneshot(
                Request::builder()
                    .uri("/api/core/discover")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("discover response body");
        let body: Value = serde_json::from_slice(&body).expect("discover JSON body");
        assert_eq!(body["runtime"]["mode"], Value::from("oneiron_cloud"));
        assert_eq!(body["runtime"]["oneironSpendMetered"], Value::from(true));
        assert!(
            body["runtime"]["routes"]
                .as_array()
                .expect("runtime routes array")
                .iter()
                .all(
                    |route| route["providerKind"].as_str() == Some("oneiron_cloud")
                        && route["oneironSpendMetered"].as_bool() == Some(true)
                )
        );

        let health = api_routes(server)
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("health route response");
        assert_eq!(health.status(), StatusCode::OK);
        let body = to_bytes(health.into_body(), usize::MAX)
            .await
            .expect("health response body");
        let body: Value = serde_json::from_slice(&body).expect("health JSON body");
        assert_eq!(body["runtime"]["mode"], Value::from("oneiron_cloud"));
        assert_eq!(body["runtime"]["oneironSpendMetered"], Value::from(true));
        assert!(body["runtime"].get("routes").is_none());
    }

    fn json_request(method: &str, uri: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request")
    }

    fn core_request(method: &str, uri: &str, scope: &str, body: Option<&Value>) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(AUTHORIZATION, format!("Bearer secret;scope={scope}"));
        if body.is_some() {
            builder = builder.header(CONTENT_TYPE, "application/json");
        }
        builder
            .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
            .expect("request")
    }

    async fn route_json(server: Arc<SyncServer>, request: Request<Body>) -> (StatusCode, Value) {
        let response = api_routes(server)
            .oneshot(request)
            .await
            .expect("route response");
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("JSON response body");
        let body: Value = serde_json::from_slice(&body).expect("JSON response");
        (status, body)
    }

    fn error_envelope(body: &Value) -> &Value {
        body.get("error")
            .and_then(Value::as_object)
            .map(|_| &body["error"])
            .expect("typed error envelope")
    }

    fn assert_error_envelope(body: &Value, code: &str) {
        let error = error_envelope(body);
        assert_eq!(error["code"], Value::from(code));
        assert!(
            error["requestId"]
                .as_str()
                .is_some_and(|request_id| !request_id.is_empty()),
            "enveloped errors must include a requestId: {body:?}"
        );
        assert!(
            body.get("code").is_none(),
            "v1 core errors must not serialize as a flat ApiError: {body:?}"
        );
    }

    fn assert_json_snapshot(actual: Value, fixture: &str, path: &str, label: &str) {
        assert_json_snapshot_with_update(
            actual,
            fixture,
            path,
            label,
            std::env::var_os("ONEIRON_UPDATE_TEST_FIXTURES").is_some(),
        );
    }

    fn assert_json_snapshot_with_update(
        mut actual: Value,
        fixture: &str,
        path: &str,
        label: &str,
        update_fixture: bool,
    ) {
        let mut expected: Value = serde_json::from_str(fixture).expect("snapshot fixture JSON");
        sort_json(&mut actual);
        let actual = serde_json::to_string_pretty(&actual).expect("serialize actual snapshot");
        if update_fixture {
            std::fs::write(path, format!("{actual}\n")).expect("write snapshot fixture");
            return;
        }
        let actual: Value = serde_json::from_str(&actual).expect("actual snapshot JSON");
        sort_json(&mut expected);
        if actual != expected {
            let actual = serde_json::to_string_pretty(&actual).expect("serialize actual snapshot");
            panic!("{label} snapshot drifted; update fixture with:\n{actual}");
        }
    }

    #[test]
    fn assert_json_snapshot_update_writes_fixture_without_comparing_stale_fixture() {
        let dir = tempfile::tempdir().expect("temp snapshot dir");
        let path = dir.path().join("snapshot.json");
        let path = path.to_str().expect("snapshot path should be UTF-8");

        assert_json_snapshot_with_update(
            json!({ "updated": true }),
            r#"{ "stale": true }"#,
            path,
            "fixture update",
            true,
        );

        let written = std::fs::read_to_string(path).expect("read updated fixture");
        let written: Value = serde_json::from_str(&written).expect("updated fixture JSON");
        assert_eq!(written, json!({ "updated": true }));
    }

    fn sort_json(value: &mut Value) {
        match value {
            Value::Array(items) => {
                for item in items {
                    sort_json(item);
                }
            }
            Value::Object(object) => {
                let mut entries = std::mem::take(object).into_iter().collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| left.cmp(right));

                for (key, mut value) in entries {
                    sort_json(&mut value);
                    object.insert(key, value);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    #[test]
    fn sort_json_orders_object_keys_recursively() {
        let mut value = json!({
            "z": {
                "nested_z": true,
                "nested_a": true
            },
            "a": [
                {
                    "array_z": true,
                    "array_a": true
                }
            ]
        });

        sort_json(&mut value);

        let serialized = serde_json::to_string(&value).expect("serialize sorted JSON");
        assert_eq!(
            serialized,
            r#"{"a":[{"array_a":true,"array_z":true}],"z":{"nested_a":true,"nested_z":true}}"#
        );
    }

    fn normalize_contract_body(body: &mut Value) {
        match body {
            Value::Array(items) => {
                for item in items {
                    normalize_contract_body(item);
                }
            }
            Value::Object(object) => {
                for (key, value) in object {
                    match key.as_str() {
                        "deleted_at" => *value = Value::from("<deleted-at>"),
                        "query_time_us" => *value = Value::from("<duration-us>"),
                        "request_id" => *value = Value::from("<request-id>"),
                        "requestId" => *value = Value::from("<request-id>"),
                        "retrieval_run_id" => *value = Value::from("<retrieval-run-id>"),
                        _ => normalize_contract_body(value),
                    }
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    fn contract_exchange(
        name: &str,
        method: &str,
        path: &str,
        auth_scope: Option<&str>,
        request_body: Option<Value>,
        status: StatusCode,
        mut response_body: Value,
    ) -> Value {
        normalize_contract_body(&mut response_body);
        json!({
            "name": name,
            "request": {
                "method": method,
                "path": path,
                "auth": auth_scope.map_or_else(
                    || json!({ "type": "none" }),
                    |scope| json!({ "type": "bearer", "scope": scope }),
                ),
                "body": request_body.unwrap_or(Value::Null),
            },
            "response": {
                "status": status.as_u16(),
                "body": response_body,
            },
        })
    }

    fn openapi_operation_contract(operation: &Value) -> Value {
        let responses = operation["responses"]
            .as_object()
            .expect("responses object")
            .iter()
            .map(|(status, response)| {
                (
                    status.clone(),
                    json!({
                        "description": response["description"].clone(),
                        "schema": openapi_json_schema_ref(response),
                    }),
                )
            })
            .collect::<Map<_, _>>();
        let parameters = operation["parameters"]
            .as_array()
            .map(|parameters| {
                parameters
                    .iter()
                    .map(|parameter| {
                        json!({
                            "name": parameter["name"].clone(),
                            "in": parameter["in"].clone(),
                            "required": parameter["required"].clone(),
                            "schema": openapi_schema_shape(&parameter["schema"]),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        json!({
            "operationId": operation["operationId"].clone(),
            "security": operation["security"].clone(),
            "parameters": parameters,
            "requestSchema": operation
                .get("requestBody")
                .map(openapi_json_schema_ref)
                .unwrap_or(Value::Null),
            "responses": responses,
        })
    }

    fn openapi_json_schema_ref(value: &Value) -> Value {
        value
            .pointer("/content/application~1json/schema")
            .map(openapi_schema_shape)
            .unwrap_or(Value::Null)
    }

    fn openapi_component_schema<'a>(spec: &'a Value, name: &str) -> &'a Value {
        spec.pointer(&format!("/components/schemas/{name}"))
            .unwrap_or_else(|| panic!("OpenAPI component schema {name} must exist"))
    }

    fn openapi_schema_contract(schema: &Value) -> Value {
        let mut contract = Map::new();
        for key in [
            "$ref",
            "type",
            "format",
            "enum",
            "const",
            "required",
            "default",
            "nullable",
            "additionalProperties",
            "discriminator",
        ] {
            if let Some(value) = schema.get(key) {
                contract.insert(key.to_owned(), value.clone());
            }
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            let mut property_contract = Map::new();
            for (name, property) in properties {
                property_contract.insert(name.clone(), openapi_schema_contract(property));
            }
            contract.insert("properties".to_owned(), Value::Object(property_contract));
        }
        if let Some(items) = schema.get("items") {
            contract.insert("items".to_owned(), openapi_schema_contract(items));
        }
        for key in ["oneOf", "anyOf", "allOf"] {
            if let Some(schemas) = schema.get(key).and_then(Value::as_array) {
                contract.insert(
                    key.to_owned(),
                    Value::Array(schemas.iter().map(openapi_schema_contract).collect()),
                );
            }
        }
        Value::Object(contract)
    }

    fn openapi_schema_shape(schema: &Value) -> Value {
        let mut shape = Map::new();
        for key in ["$ref", "type", "format", "enum", "required", "default"] {
            if let Some(value) = schema.get(key) {
                shape.insert(key.to_owned(), value.clone());
            }
        }
        if let Some(items) = schema.get("items") {
            shape.insert("items".to_owned(), openapi_schema_shape(items));
        }
        if let Some(one_of) = schema.get("oneOf").and_then(Value::as_array) {
            shape.insert(
                "oneOf".to_owned(),
                Value::Array(one_of.iter().map(openapi_schema_shape).collect()),
            );
        }
        Value::Object(shape)
    }

    fn collect_schema_refs(value: &Value, refs: &mut BTreeSet<String>) {
        match value {
            Value::Array(items) => {
                for item in items {
                    collect_schema_refs(item, refs);
                }
            }
            Value::Object(object) => {
                if let Some(name) = object
                    .get("$ref")
                    .and_then(Value::as_str)
                    .and_then(|reference| reference.strip_prefix("#/components/schemas/"))
                {
                    refs.insert(name.to_owned());
                }
                for value in object.values() {
                    collect_schema_refs(value, refs);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    async fn core_json(
        server: Arc<SyncServer>,
        method: &str,
        uri: &str,
        scope: &str,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        route_json(server, core_request(method, uri, scope, body)).await
    }

    fn seed_turn(server: &SyncServer, text: &str) -> oneiron::EntityId {
        let turn = oneiron::EntityId::now();
        let body = rmp_serde::to_vec_named(&json!({
            "txt": text,
            "spkr": "user",
            "at": 100_u64,
        }))
        .expect("encode turn body");
        server
            .vault
            .put_entity(
                &turn,
                ENTITY_TYPE_TURN,
                oneiron::TimeRange {
                    start: 100,
                    end: 100,
                },
                100,
                &body,
            )
            .expect("put turn");
        turn
    }

    fn turn_annotation_request_body(turn: &oneiron::EntityId, annotated_at: u64) -> Value {
        json!({
            "turn_id": turn.to_hex(),
            "source": "model_inference",
            "vad": {
                "valence": 0.25,
                "arousal": 0.5,
                "dominance": 0.75,
            },
            "annotated_at": annotated_at,
        })
    }

    async fn idempotent_core_annotate(
        server: Arc<SyncServer>,
        idempotency_key: &str,
        auth_header: (&str, &str),
        body: &Value,
    ) -> (StatusCode, Value) {
        route_json(
            server,
            Request::builder()
                .method("POST")
                .uri("/v1/core/turns/annotate")
                .header(auth_header.0, auth_header.1)
                .header("Idempotency-Key", idempotency_key)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
    }

    #[test]
    fn v1_core_openapi_contract_snapshot_matches_fixture() {
        let spec = generated_spec();
        let mut paths = Map::new();
        for &(path, method) in V1_CORE_OPENAPI_CONTRACT_OPERATIONS {
            paths
                .entry(path.to_owned())
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .expect("path item object")
                .insert(
                    method.to_owned(),
                    openapi_operation_contract(&spec["paths"][path][method]),
                );
        }

        let mut schemas = Map::new();
        for name in V1_CORE_OPENAPI_CONTRACT_SCHEMA_NAMES {
            schemas.insert(
                (*name).to_owned(),
                openapi_schema_contract(openapi_component_schema(&spec, name)),
            );
        }

        assert_json_snapshot(
            json!({
                "paths": paths,
                "components": {
                    "schemas": schemas,
                    "securitySchemes": {
                        "CoreBearer": spec["components"]["securitySchemes"]["CoreBearer"].clone(),
                        "OneironSecret": spec["components"]["securitySchemes"]["OneironSecret"].clone(),
                    },
                },
            }),
            V1_CORE_OPENAPI_CONTRACT_SNAPSHOT,
            V1_CORE_OPENAPI_CONTRACT_SNAPSHOT_PATH,
            "v1 core OpenAPI contract",
        );
    }

    #[test]
    fn v1_core_openapi_contract_snapshots_referenced_schemas() {
        let spec = generated_spec();
        let mut references = BTreeSet::new();
        for &(path, method) in V1_CORE_OPENAPI_CONTRACT_OPERATIONS {
            collect_schema_refs(
                &openapi_operation_contract(&spec["paths"][path][method]),
                &mut references,
            );
        }
        for name in V1_CORE_OPENAPI_CONTRACT_SCHEMA_NAMES {
            collect_schema_refs(
                &openapi_schema_contract(openapi_component_schema(&spec, name)),
                &mut references,
            );
        }

        let missing = references
            .into_iter()
            .filter(|name| !V1_CORE_OPENAPI_CONTRACT_SCHEMA_NAMES.contains(&name.as_str()))
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "OpenAPI contract references unsnapshotted schemas: {missing:?}"
        );
    }

    #[test]
    fn v1_core_openapi_documents_invalid_state_envelopes() {
        let spec = generated_spec();
        let turn_create_post_responses =
            spec["paths"]["/v1/core/conversations/{conversation_id}/turns"]["post"]["responses"]
                .as_object()
                .expect("turn create POST responses object");
        assert!(
            turn_create_post_responses.contains_key("409"),
            "turn create POST must document INVALID_STATE conflict responses"
        );
        assert_eq!(
            turn_create_post_responses["409"]["content"]["application/json"]["schema"]["$ref"],
            Value::from("#/components/schemas/ApiErrorEnvelope"),
            "turn create 409 must use the ApiErrorEnvelope schema"
        );

        let turn_annotate_post_responses =
            spec["paths"]["/v1/core/turns/annotate"]["post"]["responses"]
                .as_object()
                .expect("turn annotate POST responses object");
        assert!(
            turn_annotate_post_responses.contains_key("409"),
            "turn annotate POST must document Gate INVALID_STATE conflict responses"
        );
        assert_eq!(
            turn_annotate_post_responses["409"]["content"]["application/json"]["schema"]["$ref"],
            Value::from("#/components/schemas/ApiErrorEnvelope"),
            "turn annotate 409 must use the ApiErrorEnvelope schema"
        );
    }

    #[test]
    fn v1_core_openapi_contract_preserves_nested_error_schema_fidelity() {
        let spec = generated_spec();
        let envelope = openapi_schema_contract(openapi_component_schema(&spec, "ApiErrorEnvelope"));
        assert!(
            envelope
                .pointer("/properties/error/properties/code/enum")
                .and_then(Value::as_array)
                .is_some_and(|codes| codes.len() == ErrorCode::ALL.len()),
            "ApiErrorEnvelope.error.code must snapshot the full ErrorCode enum: {envelope}"
        );
        assert!(
            envelope
                .pointer("/properties/error/properties/details/oneOf")
                .and_then(Value::as_array)
                .is_some_and(|variants| variants.len() == ErrorCode::ALL.len()),
            "ApiErrorEnvelope.error.details must snapshot all ApiErrorDetails variants: {envelope}"
        );

        let api_error = openapi_schema_contract(openapi_component_schema(&spec, "ApiError"));
        assert!(
            api_error
                .pointer("/properties/code/enum")
                .and_then(Value::as_array)
                .is_some_and(|codes| codes.len() == ErrorCode::ALL.len()),
            "ApiError.code must snapshot the full ErrorCode enum: {api_error}"
        );
        assert!(
            api_error
                .pointer("/properties/details/oneOf")
                .and_then(Value::as_array)
                .is_some_and(|variants| variants.len() == ErrorCode::ALL.len()),
            "ApiError.details must snapshot all ApiErrorDetails variants: {api_error}"
        );

        let api_error_details =
            openapi_schema_contract(openapi_component_schema(&spec, "ApiErrorDetails"));
        assert!(
            api_error_details
                .pointer("/oneOf")
                .and_then(Value::as_array)
                .is_some_and(|variants| variants.len() == ErrorCode::ALL.len()),
            "ApiErrorDetails must snapshot all error detail variants: {api_error_details}"
        );

        let error_code = openapi_schema_contract(openapi_component_schema(&spec, "ErrorCode"));
        assert!(
            error_code
                .pointer("/enum")
                .and_then(Value::as_array)
                .is_some_and(|codes| codes.len() == ErrorCode::ALL.len()),
            "ErrorCode must snapshot the full enum catalog: {error_code}"
        );
    }

    #[tokio::test]
    async fn v1_core_success_contract_snapshot_matches_fixture() {
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        });
        let batch_id = seeded_test_entity_id(0x1221_0001).to_hex();
        let conversation_id = seeded_test_entity_id(0x1221_0002).to_hex();
        let turn_id = seeded_test_entity_id(0x1221_0003).to_hex();
        let mut exchanges = Vec::new();

        let batch_request = json!({
            "entities": [{
                "id": batch_id,
                "entity_type": ENTITY_TYPE_TURN,
                "occurred_start": 1_782_357_600_u64,
                "occurred_end": 1_782_357_600_u64,
                "learned_at": 1_782_357_635_u64,
                "body": {
                    "txt": "blue hallway contractneedle",
                    "spkr": "user",
                    "at": 1_782_357_600_u64
                },
                "text": [{ "field": "body", "value": "blue hallway contractneedle" }]
            }]
        });
        let (status, body) = core_json(
            server.clone(),
            "POST",
            "/v1/core/batch",
            "core:write",
            Some(&batch_request),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        exchanges.push(contract_exchange(
            "core_batch",
            "POST",
            "/v1/core/batch",
            Some("core:write"),
            Some(batch_request),
            status,
            body,
        ));

        let query_request = json!({
            "query": "contractneedle",
            "limit": 3,
            "view": "full",
            "countMode": "estimate"
        });
        let (status, body) = core_json(
            server.clone(),
            "POST",
            "/v1/core/query",
            "core:read",
            Some(&query_request),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        exchanges.push(contract_exchange(
            "core_query",
            "POST",
            "/v1/core/query",
            Some("core:read"),
            Some(query_request),
            status,
            body,
        ));

        let context_pack_request = json!({
            "query": "contractneedle",
            "limit": 3,
            "view": "full",
            "include_edges": false
        });
        let (status, context_pack_body) = core_json(
            server.clone(),
            "POST",
            "/v1/core/context-pack",
            "core:read",
            Some(&context_pack_request),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let context_entity = &context_pack_body["results"][0];
        let short_ref = format!(
            "{}:{}",
            context_entity["short_id"].as_str().expect("short id"),
            context_entity["content_hash"]
                .as_str()
                .expect("content hash")
        );
        exchanges.push(contract_exchange(
            "core_context_pack",
            "POST",
            "/v1/core/context-pack",
            Some("core:read"),
            Some(context_pack_request),
            status,
            context_pack_body,
        ));

        let hydrate_request = json!({
            "ref": short_ref,
            "view": "full"
        });
        let (status, body) = core_json(
            server.clone(),
            "POST",
            "/v1/core/hydrate",
            "core:read",
            Some(&hydrate_request),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        exchanges.push(contract_exchange(
            "core_hydrate",
            "POST",
            "/v1/core/hydrate",
            Some("core:read"),
            Some(hydrate_request),
            status,
            body,
        ));

        let conversation_request = json!({
            "id": conversation_id,
            "occurred_start": 1_782_357_700_u64,
            "occurred_end": 1_782_357_700_u64,
            "learned_at": 1_782_357_735_u64,
            "body": { "name": "Contract dream" },
            "text": [{ "field": "name", "value": "Contract dream" }]
        });
        let (status, body) = core_json(
            server.clone(),
            "POST",
            "/v1/core/conversations",
            "core:write",
            Some(&conversation_request),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        exchanges.push(contract_exchange(
            "create_core_conversation",
            "POST",
            "/v1/core/conversations",
            Some("core:write"),
            Some(conversation_request),
            status,
            body,
        ));

        let conversations_path = "/v1/core/conversations?view=full&limit=5&countMode=exact";
        let (status, body) =
            core_json(server.clone(), "GET", conversations_path, "core:read", None).await;
        assert_eq!(status, StatusCode::OK);
        exchanges.push(contract_exchange(
            "list_core_conversations",
            "GET",
            conversations_path,
            Some("core:read"),
            None,
            status,
            body,
        ));

        let turn_request = json!({
            "id": turn_id,
            "occurred_start": 1_782_357_800_u64,
            "occurred_end": 1_782_357_800_u64,
            "learned_at": 1_782_357_835_u64,
            "body": {
                "txt": "turn contract envelope",
                "spkr": "assistant",
                "at": 1_782_357_800_u64
            },
            "text": [{ "field": "body", "value": "turn contract envelope" }]
        });
        let turns_path = format!("/v1/core/conversations/{conversation_id}/turns");
        let (status, body) = core_json(
            server.clone(),
            "POST",
            &turns_path,
            "core:write",
            Some(&turn_request),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        exchanges.push(contract_exchange(
            "create_core_conversation_turn",
            "POST",
            &turns_path,
            Some("core:write"),
            Some(turn_request),
            status,
            body,
        ));

        let list_turns_path =
            format!("/v1/core/conversations/{conversation_id}/turns?view=full&limit=5");
        let (status, body) =
            core_json(server.clone(), "GET", &list_turns_path, "core:read", None).await;
        assert_eq!(status, StatusCode::OK);
        exchanges.push(contract_exchange(
            "list_core_conversation_turns",
            "GET",
            &list_turns_path,
            Some("core:read"),
            None,
            status,
            body,
        ));

        let get_turn_path = format!("/v1/core/turns/{turn_id}?view=full");
        let (status, body) =
            core_json(server.clone(), "GET", &get_turn_path, "core:read", None).await;
        assert_eq!(status, StatusCode::OK);
        exchanges.push(contract_exchange(
            "get_core_turn",
            "GET",
            &get_turn_path,
            Some("core:read"),
            None,
            status,
            body,
        ));

        let annotate_request = json!({
            "turn_id": turn_id,
            "source": "model_inference",
            "vad": {
                "valence": 0.25,
                "arousal": 0.5,
                "dominance": 0.75
            },
            "annotated_at": 1_782_357_900_u64
        });
        let (status, body) = core_json(
            server.clone(),
            "POST",
            "/v1/core/turns/annotate",
            "core:write",
            Some(&annotate_request),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        exchanges.push(contract_exchange(
            "annotate_turn_vad",
            "POST",
            "/v1/core/turns/annotate",
            Some("core:write"),
            Some(annotate_request),
            status,
            body,
        ));

        let read_annotation_path = format!("/v1/core/turns/annotate?turn_id={turn_id}");
        let (status, body) =
            core_json(server, "GET", &read_annotation_path, "core:read", None).await;
        assert_eq!(status, StatusCode::OK);
        exchanges.push(contract_exchange(
            "read_turn_vad_annotation",
            "GET",
            &read_annotation_path,
            Some("core:read"),
            None,
            status,
            body,
        ));

        assert_json_snapshot(
            Value::Array(exchanges),
            V1_CORE_SUCCESS_CONTRACT_SNAPSHOT,
            V1_CORE_SUCCESS_CONTRACT_SNAPSHOT_PATH,
            "v1 core success contract",
        );
    }

    #[tokio::test]
    async fn v1_core_error_contract_snapshot_matches_fixture() {
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        });
        let missing_id = seeded_test_entity_id(0x1221_00ff).to_hex();
        let deleted_id = seeded_test_entity_id(0x1221_dead);
        let deleted_body = rmp_serde::to_vec_named(&json!({
            "txt": "deleted contract turn",
            "spkr": "user",
            "at": 1_782_358_000_u64,
        }))
        .expect("encode deleted turn");
        server
            .vault
            .batch()
            .put(
                &deleted_id,
                ENTITY_TYPE_TURN,
                oneiron::TimeRange {
                    start: 1_782_358_000_u64,
                    end: 1_782_358_000_u64,
                },
                1_782_358_000_u64,
                &deleted_body,
            )
            .text(&deleted_id, &[("body", "deleted contract turn")])
            .commit()
            .expect("seed deleted turn");
        let deleted_pack = server
            .vault
            .context_pack()
            .search_text("deleted contract turn", 1)
            .run()
            .expect("deleted context pack");
        let deleted_entity = deleted_pack
            .results
            .first()
            .expect("deleted entity has short ref");
        let deleted_ref = format!(
            "{}:{:02x}",
            deleted_entity.short_id, deleted_entity.content_hash
        );
        server
            .vault
            .delete_entity_with_reason(&deleted_id, oneiron::DeleteReason::UserDelete)
            .expect("delete seeded turn");

        let mut exchanges = Vec::new();

        let malformed_request = json!({ "ref": "bad-ref" });
        let (status, body) = core_json(
            server.clone(),
            "POST",
            "/v1/core/hydrate",
            "core:read",
            Some(&malformed_request),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_error_envelope(&body, "BAD_REQUEST");
        exchanges.push(contract_exchange(
            "malformed_request",
            "POST",
            "/v1/core/hydrate",
            Some("core:read"),
            Some(malformed_request),
            status,
            body,
        ));

        let missing_auth_path = "/v1/core/turns/annotate?turn_id=not-an-entity";
        let (status, body) = route_json(
            server.clone(),
            Request::builder()
                .uri(missing_auth_path)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_error_envelope(&body, "UNAUTHORIZED");
        exchanges.push(contract_exchange(
            "missing_auth",
            "GET",
            missing_auth_path,
            None,
            None,
            status,
            body,
        ));

        let wrong_scope_path = "/v1/core/turns/annotate?turn_id=not-an-entity";
        let (status, body) =
            core_json(server.clone(), "GET", wrong_scope_path, "core:write", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_error_envelope(&body, "FORBIDDEN");
        exchanges.push(contract_exchange(
            "wrong_scope",
            "GET",
            wrong_scope_path,
            Some("core:write"),
            None,
            status,
            body,
        ));

        let not_found_path = format!("/v1/core/turns/{missing_id}");
        let (status, body) =
            core_json(server.clone(), "GET", &not_found_path, "core:read", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_error_envelope(&body, "NOT_FOUND");
        exchanges.push(contract_exchange(
            "not_found",
            "GET",
            &not_found_path,
            Some("core:read"),
            None,
            status,
            body,
        ));

        let deleted_request = json!({ "ref": deleted_ref });
        let (status, body) = core_json(
            server,
            "POST",
            "/v1/core/hydrate",
            "core:read",
            Some(&deleted_request),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], Value::from("deleted"));
        assert!(body.get("item").is_none());
        exchanges.push(contract_exchange(
            "deleted_entity",
            "POST",
            "/v1/core/hydrate",
            Some("core:read"),
            Some(deleted_request),
            status,
            body,
        ));

        assert_json_snapshot(
            Value::Array(exchanges),
            V1_CORE_ERROR_CONTRACT_SNAPSHOT,
            V1_CORE_ERROR_CONTRACT_SNAPSHOT_PATH,
            "v1 core error contract",
        );
    }

    async fn top_up_route(
        server: Arc<SyncServer>,
        idempotency_key: &str,
        credit_units: f64,
    ) -> (StatusCode, Value) {
        route_json(
            server,
            json_request(
                "POST",
                "/v1/consumer/top-up",
                json!({
                    "tenantId": "tenant-a",
                    "idempotencyKey": idempotency_key,
                    "creditUnits": credit_units,
                }),
            ),
        )
        .await
    }

    async fn record_usage_event_route(
        server: Arc<SyncServer>,
        idempotency_key: &str,
        service_cost_usd: f64,
    ) -> (StatusCode, Value) {
        record_usage_event_for_vault_route(server, idempotency_key, "vault-a", service_cost_usd)
            .await
    }

    async fn record_usage_event_for_vault_route(
        server: Arc<SyncServer>,
        idempotency_key: &str,
        vault_id: &str,
        service_cost_usd: f64,
    ) -> (StatusCode, Value) {
        route_json(
            server,
            json_request(
                "POST",
                "/v1/usage/events",
                json!({
                    "tenantId": "tenant-a",
                    "vaultId": vault_id,
                    "idempotencyKey": idempotency_key,
                    "agentId": "agent-a",
                    "model": "model-a",
                    "service": "inference",
                    "serviceCostUsd": service_cost_usd,
                }),
            ),
        )
        .await
    }

    #[test]
    fn generated_openapi_has_descriptions_examples_and_defaults() {
        let spec = generated_spec();

        assert!(
            spec["openapi"]
                .as_str()
                .is_some_and(|v| v.starts_with("3.1")),
            "OpenAPI version should start with 3.1: {:?}",
            spec["openapi"]
        );

        let paths = spec["paths"].as_object().expect("paths object");
        for path in [
            "/api/openapi.json",
            "/api/skills/oneiron.skills.md",
            "/api/core/discover",
            "/api/search/vector",
            "/api/search/text",
            "/api/entity/{id}",
            "/api/edges/{id}",
            "/v1/core/batch",
            "/v1/core/query",
            "/v1/core/context-pack",
            "/v1/core/hydrate",
            "/v1/core/conversations",
            "/v1/core/conversations/{conversation_id}/turns",
            "/v1/core/turns/{turn_id}",
            "/v1/core/turns/annotate",
            "/v1/companion/access-grants",
            "/v1/companion/access-grants/{grant_id}/revoke",
            "/v1/companion/profiles/{persona_ref}",
            "/v1/companion/register/records",
            "/v1/companion/register/records/{record_id}",
            "/v1/companion/register/records/{record_id}/retire",
            "/api/context-pack",
            "/api/lease/revoke",
            "/api/health",
            "/v1/consumer/usage",
            "/v1/consumer/usage/details",
            "/v1/consumer/top-up",
        ] {
            assert!(paths.contains_key(path), "missing path {path}");
        }

        let vector_success = &spec["paths"]["/api/search/vector"]["get"]["responses"]["200"]["content"]
            ["application/json"];
        assert!(
            vector_success.get("example").is_some() || vector_success.get("examples").is_some(),
            "vector search 200 response must include an example: {vector_success:?}"
        );
        let vector_example = &vector_success["example"];
        assert!(
            vector_example["items"].is_array(),
            "vector search example must show paginated items: {vector_example:?}"
        );
        assert_eq!(
            vector_example["meta"]["countMode"],
            Value::from("estimate"),
            "vector search example must show estimate count metadata"
        );

        let discover_success = &spec["paths"]["/api/core/discover"]["get"]["responses"]["200"]["content"]
            ["application/json"];
        assert!(
            discover_success.get("example").is_some() || discover_success.get("examples").is_some(),
            "discover 200 response must include an example: {discover_success:?}"
        );

        let skills_pack_success = &spec["paths"]["/api/skills/oneiron.skills.md"]["get"]["responses"]
            ["200"]["content"][skills_pack_artifact::MEDIA_TYPE];
        assert!(
            skills_pack_success.get("example").is_some()
                || skills_pack_success.get("examples").is_some(),
            "skills pack 200 response must include a markdown example: {skills_pack_success:?}"
        );
        let skills_pack_unauthorized = &spec["paths"]["/api/skills/oneiron.skills.md"]["get"]["responses"]
            ["401"]["content"]["application/json"]["example"];
        assert_eq!(
            skills_pack_unauthorized,
            &serde_json::to_value(ApiError::unauthorized()).expect("serialize ApiError"),
            "skills pack 401 response example must match ApiError::unauthorized()"
        );

        assert!(
            spec["paths"]["/api/core/discover"]["get"]["responses"]
                .as_object()
                .is_some_and(|responses| responses.contains_key("401")),
            "discover must document its 401 ApiError response"
        );
        assert_eq!(
            discover_success["example"]["skill_pack"]["endpoint"],
            Value::from("/api/skills/oneiron.skills.md"),
            "discover example must advertise the committed skill pack endpoint"
        );
        let turn_annotate_post_responses =
            spec["paths"]["/v1/core/turns/annotate"]["post"]["responses"]
                .as_object()
                .expect("turn annotate POST responses object");
        assert!(
            turn_annotate_post_responses.contains_key("409"),
            "turn annotate POST must document Gate INVALID_STATE conflict responses"
        );
        assert_eq!(
            turn_annotate_post_responses["409"]["content"]["application/json"]["schema"]["$ref"],
            Value::from("#/components/schemas/ApiErrorEnvelope"),
            "turn annotate 409 must use the ApiErrorEnvelope schema"
        );
        let context_pack_responses = spec["paths"]["/api/context-pack"]["post"]["responses"]
            .as_object()
            .expect("context-pack responses object");
        assert!(
            context_pack_responses.contains_key("200"),
            "context-pack must document its live success response"
        );
        assert!(
            context_pack_responses.contains_key("400"),
            "context-pack must document fail-closed malformed-control responses"
        );
        assert!(
            !context_pack_responses.contains_key("501"),
            "context-pack must not document the retired not-implemented response"
        );
        assert_eq!(
            spec["components"]["schemas"]["DiscoverResponse"]["properties"]["skill_pack"]["$ref"],
            Value::from("#/components/schemas/SkillPackDiscovery"),
            "DiscoverResponse must reference the skill-pack discovery schema"
        );

        assert_eq!(
            spec["components"]["securitySchemes"]["OneironSecret"]["name"],
            Value::from("x-oneiron-secret"),
            "protected operations must document the x-oneiron-secret auth header"
        );
        assert_eq!(
            spec["components"]["securitySchemes"]["CoreBearer"]["scheme"],
            Value::from("bearer"),
            "v1 core operations must document bearer auth"
        );
        for (path, method) in [
            ("/api/openapi.json", "get"),
            ("/api/skills/oneiron.skills.md", "get"),
            ("/api/core/discover", "get"),
            ("/api/search/vector", "get"),
            ("/api/search/text", "get"),
            ("/api/entity/{id}", "get"),
            ("/api/edges/{id}", "get"),
            ("/api/context-pack", "post"),
            ("/api/lease/revoke", "post"),
            ("/v1/consumer/usage", "get"),
            ("/v1/consumer/usage/details", "get"),
            ("/v1/consumer/top-up", "post"),
        ] {
            assert_eq!(
                spec["paths"][path][method]["security"],
                json!([{ "OneironSecret": [] }]),
                "{method} {path} must require OneironSecret"
            );
        }
        for (path, method) in [
            ("/v1/core/batch", "post"),
            ("/v1/core/query", "post"),
            ("/v1/core/context-pack", "post"),
            ("/v1/core/hydrate", "post"),
            ("/v1/core/batch/shortId/hydrate", "post"),
            ("/v1/core/conversations", "get"),
            ("/v1/core/conversations", "post"),
            ("/v1/core/conversations/{conversation_id}/turns", "get"),
            ("/v1/core/conversations/{conversation_id}/turns", "post"),
            ("/v1/core/turns/{turn_id}", "get"),
            ("/v1/core/turns/annotate", "get"),
            ("/v1/core/turns/annotate", "post"),
            ("/v1/companion/access-grants", "post"),
            ("/v1/companion/access-grants/{grant_id}/revoke", "post"),
            ("/v1/companion/profiles/{persona_ref}", "get"),
            ("/v1/companion/register/records", "post"),
            ("/v1/companion/register/records/{record_id}", "get"),
            ("/v1/companion/register/records/{record_id}", "post"),
            ("/v1/companion/register/records/{record_id}/retire", "post"),
        ] {
            assert_eq!(
                spec["paths"][path][method]["security"],
                json!([{ "CoreBearer": [] }, { "OneironSecret": [] }]),
                "{method} {path} must accept scoped bearer auth with legacy secret fallback"
            );
        }

        assert!(
            spec["components"]["schemas"].get("ApiError").is_some(),
            "structured ApiError schema must be reusable from components"
        );
        assert!(
            spec["components"]["schemas"]
                .get("ApiErrorEnvelope")
                .is_some(),
            "v1 core ApiErrorEnvelope schema must be reusable from components"
        );
        assert!(
            spec["components"]["schemas"].get("ErrorCode").is_some(),
            "ErrorCode schema must be reusable from components"
        );
        assert!(
            spec["components"]["schemas"]["View"].get("enum").is_some(),
            "View schema must document allowed projection values"
        );

        let entity_octets = &spec["paths"]["/api/entity/{id}"]["get"]["responses"]["200"]["content"]
            ["application/octet-stream"];
        assert_eq!(
            entity_octets["example"],
            Value::from("raw entity bytes"),
            "entity octet-stream example must not be a JSON byte array"
        );
        assert_eq!(
            entity_octets["schema"],
            json!({ "type": "string", "format": "binary" }),
            "entity octet-stream schema must model raw binary"
        );

        let entity_json = &spec["paths"]["/api/entity/{id}"]["get"]["responses"]["200"]["content"]
            ["application/json"];
        assert_eq!(
            entity_json["schema"]["type"],
            Value::from("object"),
            "entity projection response must document a JSON object schema"
        );
        assert!(
            entity_json["examples"]["summary"].is_object(),
            "entity JSON projection response must include a summary example: {entity_json:?}"
        );
        assert!(
            entity_json["examples"]["full"].is_object(),
            "entity JSON projection response must include a full example: {entity_json:?}"
        );

        assert_non_empty_string(
            &spec["components"]["schemas"]["SearchResult"]["properties"]["score"]["description"],
            "SearchResult.score.description",
        );

        let lease_client_description = spec["components"]["schemas"]["LeaseRevokeRequest"]
            ["properties"]["client_id"]["description"]
            .as_str()
            .expect("LeaseRevokeRequest.client_id description");
        assert!(
            lease_client_description
                .to_ascii_lowercase()
                .contains("revoke"),
            "lease revoke client_id description should mention revoke: {lease_client_description}"
        );

        assert_eq!(
            spec["components"]["schemas"]["VectorSearchQuery"]["properties"]["limit"]["default"],
            Value::from(default_limit())
        );

        for schema_name in [
            "HealthResponse",
            "DiscoverResponse",
            "SkillPackDiscovery",
            "BoundContext",
            "DiscoveredEntity",
            "FeatureFlags",
            "RateLimitStatus",
            "RuntimeHealthStatus",
            "RuntimeStatus",
            "RuntimeRoute",
            "RuntimeRouteProvenance",
            "VectorSearchQuery",
            "SearchResult",
            "TextSearchQuery",
            "EdgeResult",
            "CoreBatchRequest",
            "CoreBatchEntityInput",
            "CoreBatchEntityResult",
            "CoreBatchResponse",
            "CoreTextField",
            "CoreQueryRequest",
            "CoreBatchShortIdHydrateItem",
            "CoreBatchShortIdHydrateRequest",
            "CoreBatchShortIdHydrateResponse",
            "CoreHydrateDeletionMetadata",
            "CoreHydrateRequest",
            "CoreHydrateResponse",
            "CoreShortIdHydrateError",
            "ContextPackDepthControls",
            "ContextPackPolicyControls",
            "ContextPackTimeControls",
            "ContextPackRetrievalBudgetControls",
            "ContextPackBudgetControls",
            "CoreContextPackRequest",
            "CoreContextPackResponse",
            "CoreContextEntity",
            "CoreContextEdge",
            "CoreContextPackStats",
            "CoreContextPackItemAccounting",
            "CoreContextPackState",
            "CoreContextPackScoreComponent",
            "CoreContextPackScoreEvidence",
            "CoreContextPackEvidence",
            "CoreListQuery",
            "CoreCreateEntityRequest",
            "CoreCreateTurnRequest",
            "CoreEntityWriteResponse",
            "VadPayload",
            "TurnVadAnnotateRequest",
            "TurnVadAnnotateQuery",
            "TurnVadAnnotateResponse",
            "CompanionAccessGrantScopePayload",
            "CompanionAccessGrantResponse",
            "CompanionCreateAccessGrantRequest",
            "CompanionRevokeAccessGrantRequest",
            "CompanionProfileAccess",
            "CompanionProfileResponse",
            "CompanionRegisterScopePayload",
            "CompanionRegisterRelationshipRefPayload",
            "CompanionRegisterSubjectPayload",
            "CompanionRegisterProvenancePayload",
            "CompanionRegisterRecordPayload",
            "CompanionRegisterCreateRecordRequest",
            "CompanionRegisterUpdateRecordRequest",
            "CompanionRegisterRetireRecordRequest",
            "CompanionRegisterRecordResponse",
            "LeaseRevokeRequest",
            "LeaseRevokeResponse",
            "ContextPackRequest",
            "ConsumerAllowanceState",
            "ConsumerAllowanceWarning",
            "ConsumerTopUp",
            "ConsumerTopUpRequest",
            "ConsumerTopUpState",
            "ConsumerUsageDetails",
            "ConsumerUsageState",
        ] {
            let properties = spec["components"]["schemas"][schema_name]["properties"]
                .as_object()
                .unwrap_or_else(|| panic!("{schema_name} properties object"));
            assert!(
                properties.values().any(|property| property
                    .get("description")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.trim().is_empty())),
                "{schema_name} must have at least one described property"
            );
            for (field_name, property) in properties {
                assert_non_empty_string(
                    &property["description"],
                    &format!("{schema_name}.{field_name}.description"),
                );
            }
        }
    }

    #[tokio::test]
    async fn openapi_route_serves_json_document() {
        let (_dir, server) = test_server();
        let response = api_routes(server)
            .oneshot(
                Request::builder()
                    .uri("/api/openapi.json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("OpenAPI response body");
        let body: Value = serde_json::from_slice(&body).expect("OpenAPI JSON body");
        assert!(
            body["openapi"]
                .as_str()
                .is_some_and(|v| v.starts_with("3.1")),
            "served OpenAPI version should start with 3.1: {:?}",
            body["openapi"]
        );
    }

    #[tokio::test]
    async fn openapi_route_uses_api_auth() {
        let dir = tempfile::tempdir().expect("temp vault dir");
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
        let server = Arc::new(SyncServer::new(vault, SyncServerConfig::default()).unwrap());
        let response = api_routes(server)
            .oneshot(
                Request::builder()
                    .uri("/api/openapi.json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("ApiError response body");
        let body: Value = serde_json::from_slice(&body).expect("ApiError JSON body");
        assert_eq!(body["code"], Value::from("UNAUTHORIZED"));
    }

    #[tokio::test]
    async fn v1_core_route_missing_auth_returns_typed_error_envelope() {
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        });

        let (status, body) = route_json(
            server,
            Request::builder()
                .uri("/v1/core/turns/annotate?turn_id=not-an-entity")
                .body(Body::empty())
                .expect("request"),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_error_envelope(&body, "UNAUTHORIZED");
        assert_eq!(error_envelope(&body)["details"]["code"], "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn v1_core_idempotency_preflight_uses_typed_error_envelope() {
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        });

        let (status, body) = route_json(
            server,
            Request::builder()
                .method("POST")
                .uri("/v1/core/turns/annotate")
                .header("Idempotency-Key", "idem-1")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "turn_id": "not-an-entity",
                        "source": "model_inference",
                        "vad": {
                            "valence": 0.0,
                            "arousal": 0.0,
                            "dominance": 0.0,
                        },
                        "annotated_at": 1_u64,
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_error_envelope(&body, "UNAUTHORIZED");
    }

    #[tokio::test]
    async fn v1_core_route_rejects_valid_bearer_without_required_scope() {
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        });

        let (status, body) = route_json(
            server,
            Request::builder()
                .uri("/v1/core/turns/annotate?turn_id=not-an-entity")
                .header(AUTHORIZATION, "Bearer secret;scope=core:write")
                .body(Body::empty())
                .expect("request"),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_error_envelope(&body, "FORBIDDEN");
        assert_eq!(
            error_envelope(&body)["details"]["requiredScope"],
            Value::from("core:read")
        );
    }

    #[tokio::test]
    async fn v1_core_route_wraps_handler_errors_after_bearer_auth() {
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        });

        let (status, body) = route_json(
            server,
            Request::builder()
                .uri("/v1/core/turns/annotate?turn_id=not-an-entity")
                .header(AUTHORIZATION, "Bearer secret;scope=core:read")
                .body(Body::empty())
                .expect("request"),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_error_envelope(&body, "BAD_REQUEST");
        assert_eq!(
            error_envelope(&body)["details"]["field"],
            Value::from("turn_id")
        );
    }

    #[tokio::test]
    async fn v1_companion_profile_access_grants_allow_deny_and_revoke() {
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        });
        let grant_id = seeded_test_entity_id(0x1265_0001).to_hex();
        let principal_ref = seeded_test_entity_id(0x1265_0002).to_hex();
        let person_ref = seeded_test_entity_id(0x1265_0003).to_hex();
        let persona_ref = seeded_test_entity_id(0x1265_0004).to_hex();
        let other_person_ref = seeded_test_entity_id(0x1265_0005).to_hex();

        let profile_path = format!(
            "/v1/companion/profiles/{persona_ref}?principal_ref={principal_ref}&person_ref={person_ref}"
        );
        let (status, body) = route_json(
            server.clone(),
            core_request("GET", &profile_path, "core:read", None),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_error_envelope(&body, "FORBIDDEN");
        assert_eq!(
            error_envelope(&body)["details"]["requiredScope"],
            Value::from("companion_profile.read")
        );

        let create_request = json!({
            "id": grant_id,
            "principal_ref": principal_ref,
            "scope": {
                "kind": "companion_profile",
                "person_ref": person_ref,
                "persona_ref": persona_ref,
            },
            "created_at": 10_u64,
        });
        let (status, body) = route_json(
            server.clone(),
            core_request(
                "POST",
                "/v1/companion/access-grants",
                "core:auth",
                Some(&create_request),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], Value::from(grant_id.clone()));
        assert_eq!(body["status"], Value::from("active"));
        assert_eq!(body["capability"], Value::from("companion_profile.read"));

        let (status, body) = route_json(
            server.clone(),
            core_request("GET", &profile_path, "core:read", None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["access"]["grant_id"], Value::from(grant_id.clone()));
        assert_eq!(body["persona_ref"], Value::from(persona_ref.clone()));

        let wrong_scope_path = format!(
            "/v1/companion/profiles/{persona_ref}?principal_ref={principal_ref}&person_ref={other_person_ref}"
        );
        let (status, body) = route_json(
            server.clone(),
            core_request("GET", &wrong_scope_path, "core:read", None),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_error_envelope(&body, "FORBIDDEN");

        let revoke_path = format!("/v1/companion/access-grants/{grant_id}/revoke");
        let revoke_request = json!({ "revoked_at": 20_u64 });
        let (status, body) = route_json(
            server.clone(),
            core_request("POST", &revoke_path, "core:auth", Some(&revoke_request)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], Value::from("revoked"));
        assert_eq!(body["revoked_at"], Value::from(20_u64));

        let (status, body) = route_json(
            server.clone(),
            core_request(
                "POST",
                "/v1/companion/access-grants",
                "core:auth",
                Some(&create_request),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_error_envelope(&body, "INVALID_STATE");
        assert_eq!(
            error_envelope(&body)["details"]["state"],
            Value::from("access_grant_exists")
        );
        assert_eq!(
            server
                .vault
                .get_access_grant(&oneiron::EntityId::from_hex(&grant_id).expect("test grant id"))
                .expect("read grant")
                .expect("grant exists")
                .status,
            oneiron::AccessGrantStatus::Revoked
        );

        let (status, body) = route_json(
            server.clone(),
            core_request("GET", &profile_path, "core:read", None),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_error_envelope(&body, "FORBIDDEN");
    }

    #[tokio::test]
    async fn v1_companion_access_grant_create_replays_idempotency_key() {
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        });
        let principal_ref = seeded_test_entity_id(0x1265_0101).to_hex();
        let person_ref = seeded_test_entity_id(0x1265_0102).to_hex();
        let persona_ref = seeded_test_entity_id(0x1265_0103).to_hex();
        let create_request = json!({
            "principal_ref": principal_ref,
            "scope": {
                "kind": "companion_profile",
                "person_ref": person_ref,
                "persona_ref": persona_ref,
            },
            "created_at": 30_u64,
        });

        let make_request = || {
            Request::builder()
                .method("POST")
                .uri("/v1/companion/access-grants")
                .header(AUTHORIZATION, "Bearer secret;scope=core:auth")
                .header("Idempotency-Key", "companion-create-replay")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(create_request.to_string()))
                .expect("request")
        };
        let (first_status, first_body) = route_json(server.clone(), make_request()).await;
        let (replay_status, replay_body) = route_json(server.clone(), make_request()).await;

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(replay_status, StatusCode::OK);
        assert_eq!(replay_body, first_body);

        let grant_id = oneiron::EntityId::from_hex(first_body["id"].as_str().expect("grant id"))
            .expect("grant id parses");
        assert_eq!(
            server
                .vault
                .entities_by_type(oneiron::ENTITY_TYPE_ACCESS_GRANT)
                .expect("list access grants"),
            vec![grant_id]
        );
        assert_eq!(
            server
                .vault
                .companion_profile_access_grant(
                    &oneiron::EntityId::from_hex(&principal_ref).expect("principal id"),
                    &oneiron::EntityId::from_hex(&person_ref).expect("person id"),
                    &oneiron::EntityId::from_hex(&persona_ref).expect("persona id"),
                )
                .expect("grant lookup"),
            Some(grant_id)
        );
    }

    #[tokio::test]
    async fn v1_companion_register_api_create_update_read_and_retire_typed_envelopes() {
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        });
        let neutral_id = seeded_test_entity_id(0x1219_0001).to_hex();
        let personal_id = seeded_test_entity_id(0x1219_0002).to_hex();
        let shared_id = seeded_test_entity_id(0x1219_0003).to_hex();
        let actor_ref = seeded_test_entity_id(0x1219_0004).to_hex();
        let persona_ref = seeded_test_entity_id(0x1219_0005).to_hex();
        let person_ref = seeded_test_entity_id(0x1219_0006).to_hex();
        let source_ref = seeded_test_entity_id(0x1219_0007).to_hex();
        let target_ref = seeded_test_entity_id(0x1219_0008).to_hex();

        let provenance = json!({
            "actor_ref": actor_ref,
            "actor_class": 1,
            "source": "user_stated",
            "approval": "approved",
            "value": { "source": "settings" }
        });
        let neutral_record = json!({
            "kind": "persona",
            "scope": { "kind": "neutral" },
            "subject": { "kind": "persona", "persona_ref": persona_ref },
            "value": { "style": "neutral @Oneiron" },
            "provenance": provenance.clone(),
            "export": "portable"
        });
        let personal_record = json!({
            "kind": "persona",
            "scope": { "kind": "personal", "person_ref": person_ref },
            "subject": { "kind": "persona", "persona_ref": persona_ref },
            "value": { "note": "private per-person companion note" },
            "provenance": provenance.clone(),
            "export": "local_only"
        });
        let shared_record = json!({
            "kind": "relationship",
            "scope": { "kind": "shared_vault", "vault_id": 7_u64 },
            "subject": {
                "kind": "relationship",
                "relationship_ref": {
                    "source_ref": source_ref,
                    "target_ref": target_ref
                }
            },
            "value": { "note": "shared-vault boundary note" },
            "provenance": provenance,
            "export": "shared_vault"
        });

        let (status, body) = route_json(
            server.clone(),
            core_request(
                "POST",
                "/v1/companion/register/records",
                "core:write",
                Some(&json!({
                    "id": seeded_test_entity_id(0x1219_0010).to_hex(),
                    "record": neutral_record.clone()
                })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_error_envelope(&body, "FORBIDDEN");
        assert_eq!(
            error_envelope(&body)["details"]["requiredScope"],
            Value::from("companion:register:write")
        );

        for (id, record, learned_at) in [
            (&neutral_id, neutral_record.clone(), 30_u64),
            (&personal_id, personal_record.clone(), 31_u64),
            (&shared_id, shared_record.clone(), 32_u64),
        ] {
            let request = json!({ "id": id, "learned_at": learned_at, "record": record });
            let (status, body) = route_json(
                server.clone(),
                core_request(
                    "POST",
                    "/v1/companion/register/records",
                    "companion:register:write",
                    Some(&request),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["id"], Value::from(id.clone()));
            assert_eq!(body["record"]["lifecycle"], Value::from("active"));
        }

        let mut bad_record_value = personal_record.clone();
        bad_record_value["value"] = Value::from("not-an-object");
        let (status, body) = route_json(
            server.clone(),
            core_request(
                "POST",
                "/v1/companion/register/records",
                "companion:register:write",
                Some(&json!({
                    "id": seeded_test_entity_id(0x1219_000A).to_hex(),
                    "record": bad_record_value
                })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_error_envelope(&body, "BAD_REQUEST");
        assert_eq!(
            error_envelope(&body)["details"]["field"],
            Value::from("record.value")
        );

        let mut bad_provenance_value = personal_record.clone();
        bad_provenance_value["provenance"]["value"] = Value::from("not-an-object");
        let (status, body) = route_json(
            server.clone(),
            core_request(
                "POST",
                "/v1/companion/register/records",
                "companion:register:write",
                Some(&json!({
                    "id": seeded_test_entity_id(0x1219_000B).to_hex(),
                    "record": bad_provenance_value
                })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_error_envelope(&body, "BAD_REQUEST");
        assert_eq!(
            error_envelope(&body)["details"]["field"],
            Value::from("record.provenance.value")
        );

        let read_path = format!("/v1/companion/register/records/{personal_id}");
        let (status, body) = route_json(
            server.clone(),
            core_request("GET", &read_path, "core:read", None),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_error_envelope(&body, "FORBIDDEN");
        assert_eq!(
            error_envelope(&body)["details"]["requiredScope"],
            Value::from("companion:register:read")
        );

        let (status, body) = route_json(
            server.clone(),
            core_request("GET", &read_path, "companion:register:read", None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["record"]["value"]["note"],
            Value::from("private per-person companion note")
        );

        let updated_record = json!({
            "kind": "persona",
            "scope": { "kind": "personal", "person_ref": person_ref },
            "subject": { "kind": "persona", "persona_ref": persona_ref },
            "value": { "note": "updated private per-person companion note" },
            "provenance": body["record"]["provenance"].clone(),
            "export": "local_only"
        });
        let update_request = json!({ "learned_at": 33_u64, "record": updated_record });
        let (status, body) = route_json(
            server.clone(),
            core_request(
                "POST",
                &read_path,
                "companion:register:write",
                Some(&update_request),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["record"]["value"]["note"],
            Value::from("updated private per-person companion note")
        );

        let retire_path = format!("/v1/companion/register/records/{personal_id}/retire");
        let retire_request = json!({ "retired_at": 34_u64 });
        let (status, body) = route_json(
            server.clone(),
            core_request(
                "POST",
                &retire_path,
                "companion:register:write",
                Some(&retire_request),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["record"]["lifecycle"], Value::from("retracted"));

        let reactivate_request = json!({
            "learned_at": 35_u64,
            "record": {
                "kind": "persona",
                "scope": { "kind": "personal", "person_ref": person_ref },
                "subject": { "kind": "persona", "persona_ref": persona_ref },
                "value": { "note": "reactivated private note" },
                "provenance": body["record"]["provenance"].clone(),
                "export": "local_only"
            }
        });
        let (status, body) = route_json(
            server.clone(),
            core_request(
                "POST",
                &read_path,
                "companion:register:write",
                Some(&reactivate_request),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_error_envelope(&body, "BAD_REQUEST");

        let (status, body) = route_json(
            server.clone(),
            core_request(
                "POST",
                "/v1/companion/register/records",
                "companion:register:write",
                Some(&json!({
                    "id": seeded_test_entity_id(0x1219_0009).to_hex(),
                    "record": neutral_record
                })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_error_envelope(&body, "INVALID_STATE");
        assert_eq!(
            error_envelope(&body)["details"]["state"],
            Value::from("companion_record_exists")
        );

        assert!(
            server
                .vault
                .get_companion_record(
                    &oneiron::EntityId::from_hex(&shared_id).expect("shared record id")
                )
                .expect("read shared record")
                .is_some()
        );
    }

    #[tokio::test]
    async fn v1_core_idempotency_read_only_token_cannot_replay_cached_write_success() {
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        });
        let turn = seed_turn(&server, "cached write success");
        let body = turn_annotation_request_body(&turn, 300);

        let (write_status, write_body) = idempotent_core_annotate(
            server.clone(),
            "scoped-write-success",
            (AUTHORIZATION.as_str(), "Bearer secret;scope=core:write"),
            &body,
        )
        .await;
        assert_eq!(write_status, StatusCode::OK);
        assert_eq!(write_body["turn_id"], Value::from(turn.to_hex()));

        let (read_status, read_body) = idempotent_core_annotate(
            server,
            "scoped-write-success",
            (AUTHORIZATION.as_str(), "Bearer secret;scope=core:read"),
            &body,
        )
        .await;
        assert_eq!(read_status, StatusCode::FORBIDDEN);
        assert_error_envelope(&read_body, "FORBIDDEN");
        assert_eq!(
            error_envelope(&read_body)["details"]["requiredScope"],
            Value::from("core:write")
        );
    }

    #[tokio::test]
    async fn v1_core_idempotency_write_token_retry_is_not_poisoned_by_read_only_403() {
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        });
        let turn = seed_turn(&server, "read-only poison");
        let body = turn_annotation_request_body(&turn, 301);

        let (read_status, read_body) = idempotent_core_annotate(
            server.clone(),
            "scoped-read-poison",
            (AUTHORIZATION.as_str(), "Bearer secret;scope=core:read"),
            &body,
        )
        .await;
        assert_eq!(read_status, StatusCode::FORBIDDEN);
        assert_error_envelope(&read_body, "FORBIDDEN");

        let (write_status, write_body) = idempotent_core_annotate(
            server.clone(),
            "scoped-read-poison",
            (AUTHORIZATION.as_str(), "Bearer secret;scope=core:write"),
            &body,
        )
        .await;
        assert_eq!(write_status, StatusCode::OK);
        assert_eq!(write_body["turn_id"], Value::from(turn.to_hex()));
        assert!(
            server
                .vault
                .get_turn_vad_annotation(&turn)
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn v1_core_idempotency_legacy_shared_secret_still_replays_and_conflicts() {
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        });
        let turn = seed_turn(&server, "legacy idempotency");
        let body = turn_annotation_request_body(&turn, 302);

        let (first_status, first_body) = idempotent_core_annotate(
            server.clone(),
            "legacy-core-idem",
            ("x-oneiron-secret", "secret"),
            &body,
        )
        .await;
        assert_eq!(first_status, StatusCode::OK);

        let (replay_status, replay_body) = idempotent_core_annotate(
            server.clone(),
            "legacy-core-idem",
            ("x-oneiron-secret", "secret"),
            &body,
        )
        .await;
        assert_eq!(replay_status, StatusCode::OK);
        assert_eq!(replay_body, first_body);

        let changed_body = turn_annotation_request_body(&turn, 303);
        let (conflict_status, conflict_body) = idempotent_core_annotate(
            server,
            "legacy-core-idem",
            ("x-oneiron-secret", "secret"),
            &changed_body,
        )
        .await;
        assert_eq!(conflict_status, StatusCode::CONFLICT);
        assert_error_envelope(&conflict_body, "IDEMPOTENCY_REPLAY_CONFLICT");
    }

    #[tokio::test]
    async fn v1_core_batch_query_context_pack_and_hydrate_routes_are_live() {
        let (_dir, server) = test_server();

        let (batch_status, batch_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/core/batch",
                json!({
                    "entities": [{
                        "entity_type": ENTITY_TYPE_TURN,
                        "learned_at": 500_u64,
                        "occurred_start": 500_u64,
                        "occurred_end": 500_u64,
                        "body": {
                            "txt": "blue hallway contextneedle",
                            "spkr": "user",
                            "at": 500_u64
                        }
                    }]
                }),
            ),
        )
        .await;
        assert_eq!(batch_status, StatusCode::OK);
        let id = batch_body["entities"][0]["id"]
            .as_str()
            .expect("written id")
            .to_owned();
        assert_eq!(batch_body["count"], Value::from(1));

        let (query_status, query_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/core/query",
                json!({
                    "query": "contextneedle",
                    "limit": 5,
                    "view": "full"
                }),
            ),
        )
        .await;
        assert_eq!(query_status, StatusCode::OK);
        assert_eq!(query_body["items"][0]["id"], Value::from(id.clone()));
        assert_eq!(
            query_body["items"][0]["txt"],
            Value::from("blue hallway contextneedle")
        );
        assert_eq!(query_body["meta"]["countMode"], Value::from("estimate"));

        let (pack_status, pack_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/core/context-pack",
                json!({
                    "query": "contextneedle",
                    "limit": 5,
                    "view": "full"
                }),
            ),
        )
        .await;
        assert_eq!(pack_status, StatusCode::OK);
        assert_eq!(pack_body["results"][0]["id"], Value::from(id.clone()));
        assert_eq!(
            pack_body["results"][0]["fields"]["txt"],
            Value::from("blue hallway contextneedle")
        );
        assert_eq!(
            pack_body["stats"]["signals_used"],
            Value::Array(vec![Value::from("text")])
        );
        let short_id = pack_body["results"][0]["short_id"]
            .as_str()
            .expect("short id");
        let content_hash = pack_body["results"][0]["content_hash"]
            .as_str()
            .expect("content hash");
        let short_ref = format!("{short_id}:{content_hash}");

        let (hydrate_status, hydrate_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/core/hydrate",
                json!({
                    "ref": short_ref,
                    "view": "full"
                }),
            ),
        )
        .await;
        assert_eq!(hydrate_status, StatusCode::OK);
        assert_eq!(hydrate_body["status"], Value::from("live"));
        assert_eq!(hydrate_body["id"], Value::from(id.clone()));
        assert_eq!(
            hydrate_body["item"]["txt"],
            Value::from("blue hallway contextneedle")
        );
    }

    #[tokio::test]
    async fn v1_core_memory_timeline_orders_supersession_chain() {
        let (_dir, server) = test_server();
        let subject = seeded_test_entity_id(0x1261_0100);
        let old = seeded_test_entity_id(0x1261_0101);
        let new = seeded_test_entity_id(0x1261_0102);
        server
            .vault
            .put_entity(
                &subject,
                oneiron::types::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"subject",
            )
            .expect("seed subject");
        seed_active_claim(&server, old, subject, "osaka", 100);
        seed_active_claim(&server, new, subject, "tokyo", 200);
        server
            .vault
            .supersede_claim(&new, &old, 777)
            .expect("supersede claim");

        let path = format!("/v1/core/memory/{}/timeline?view=full", new.to_hex());
        let (status, body) = route_json(
            server,
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("timeline request"),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body:#}");
        assert_eq!(body["anchor_id"], Value::from(new.to_hex()));
        let records = body["records"].as_array().expect("timeline records");
        assert_eq!(records.len(), 2, "{body:#}");
        assert_eq!(records[0]["id"], Value::from(old.to_hex()));
        assert_eq!(records[0]["state"], Value::from("superseded"));
        assert_eq!(records[0]["occurred_start"], Value::from(100_u64));
        assert_eq!(records[0]["occurred_end"], Value::from(777_u64));
        assert_eq!(
            records[0]["superseded_by"],
            Value::Array(vec![Value::from(new.to_hex())])
        );
        assert_eq!(records[1]["id"], Value::from(new.to_hex()));
        assert_eq!(records[1]["state"], Value::from("live"));
        assert_eq!(
            records[1]["supersedes"],
            Value::Array(vec![Value::from(old.to_hex())])
        );
    }

    #[tokio::test]
    async fn v1_core_memory_verbs_resolve_aliases_to_typed_operations() {
        let (_dir, server) = test_server();
        let remembered = seeded_test_entity_id(0x1261_0200);
        let remember_request = json!({
            "entity": {
                "id": remembered.to_hex(),
                "entity_type": ENTITY_TYPE_TURN,
                "learned_at": 300_u64,
                "occurred_start": 300_u64,
                "occurred_end": 300_u64,
                "body": {
                    "txt": "memory verb remembered turn",
                    "spkr": "user",
                    "at": 300_u64
                },
                "text": [{ "field": "body", "value": "memory verb remembered turn" }]
            }
        });
        let (remember_status, remember_body) = route_json(
            server.clone(),
            json_request("POST", "/v1/core/memory/verbs/remember", remember_request),
        )
        .await;
        assert_eq!(remember_status, StatusCode::OK, "{remember_body:#}");
        assert_eq!(remember_body["verb"], Value::from("remember"));
        assert_eq!(remember_body["operation"], Value::from("put_entity"));
        assert_eq!(
            remember_body["entity"]["id"],
            Value::from(remembered.to_hex())
        );

        let subject = seeded_test_entity_id(0x1261_0201);
        let old = seeded_test_entity_id(0x1261_0202);
        let new = seeded_test_entity_id(0x1261_0203);
        let retractable = seeded_test_entity_id(0x1261_0204);
        server
            .vault
            .put_entity(
                &subject,
                oneiron::types::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"subject",
            )
            .expect("seed subject");
        seed_active_claim(&server, old, subject, "before", 310);
        seed_active_claim(&server, new, subject, "after", 320);
        seed_active_claim(&server, retractable, subject, "withdraw", 330);

        let (replace_status, replace_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/core/memory/verbs/replace",
                json!({
                    "new_id": new.to_hex(),
                    "old_id": old.to_hex(),
                    "at": 900_u64
                }),
            ),
        )
        .await;
        assert_eq!(replace_status, StatusCode::OK, "{replace_body:#}");
        assert_eq!(replace_body["verb"], Value::from("supersede"));
        assert_eq!(replace_body["operation"], Value::from("supersede_claim"));
        assert_eq!(replace_body["new_id"], Value::from(new.to_hex()));
        assert_eq!(replace_body["old_id"], Value::from(old.to_hex()));

        let (withdraw_status, withdraw_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/core/memory/verbs/withdraw",
                json!({
                    "id": retractable.to_hex(),
                    "at": 901_u64
                }),
            ),
        )
        .await;
        assert_eq!(withdraw_status, StatusCode::OK, "{withdraw_body:#}");
        assert_eq!(withdraw_body["verb"], Value::from("retract"));
        assert_eq!(withdraw_body["operation"], Value::from("retract_claim"));
        assert_eq!(withdraw_body["id"], Value::from(retractable.to_hex()));

        let (soft_gdpr_status, soft_gdpr_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/core/memory/verbs/delete",
                json!({
                    "id": remembered.to_hex(),
                    "reason": "gdpr_delete"
                }),
            ),
        )
        .await;
        assert_eq!(soft_gdpr_status, StatusCode::BAD_REQUEST);
        assert_error_envelope(&soft_gdpr_body, "BAD_REQUEST");

        let (soft_hard_status, soft_hard_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/core/memory/verbs/delete",
                json!({
                    "id": remembered.to_hex(),
                    "reason": "user_hard_delete"
                }),
            ),
        )
        .await;
        assert_eq!(soft_hard_status, StatusCode::BAD_REQUEST);
        assert_error_envelope(&soft_hard_body, "BAD_REQUEST");

        let (delete_at_status, delete_at_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/core/memory/verbs/delete",
                json!({
                    "id": remembered.to_hex(),
                    "at": 902_u64
                }),
            ),
        )
        .await;
        assert_eq!(delete_at_status, StatusCode::BAD_REQUEST);
        assert_error_envelope(&delete_at_body, "BAD_REQUEST");

        let (hard_user_status, hard_user_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/core/memory/verbs/hard_delete",
                json!({
                    "id": remembered.to_hex(),
                    "reason": "user_delete"
                }),
            ),
        )
        .await;
        assert_eq!(hard_user_status, StatusCode::BAD_REQUEST);
        assert_error_envelope(&hard_user_body, "BAD_REQUEST");

        let (forget_status, forget_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/core/memory/verbs/forget",
                json!({ "id": remembered.to_hex() }),
            ),
        )
        .await;
        assert_eq!(forget_status, StatusCode::OK, "{forget_body:#}");
        assert_eq!(forget_body["verb"], Value::from("delete"));
        assert_eq!(forget_body["operation"], Value::from("delete_entity"));
        assert_eq!(forget_body["delete"]["existed"], Value::from(true));
        assert_eq!(forget_body["delete"]["reason"], Value::from("user_delete"));
        assert_eq!(forget_body["delete"]["hard"], Value::from(false));
        assert!(forget_body.get("at").is_none());

        let deleted_path = format!("/v1/core/memory/{}/timeline", remembered.to_hex());
        let (timeline_status, timeline_body) = route_json(
            server,
            Request::builder()
                .uri(deleted_path)
                .body(Body::empty())
                .expect("deleted timeline request"),
        )
        .await;
        assert_eq!(timeline_status, StatusCode::OK, "{timeline_body:#}");
        let records = timeline_body["records"].as_array().expect("records");
        assert_eq!(records.len(), 1, "{timeline_body:#}");
        assert_eq!(records[0]["id"], Value::from(remembered.to_hex()));
        assert_eq!(records[0]["state"], Value::from("deleted"));
        assert_eq!(records[0]["deletion"]["reason"], Value::from("user_delete"));
        assert!(records[0].get("item").is_none());
    }

    #[tokio::test]
    async fn v1_core_hydrate_distinguishes_malformed_not_found_and_deleted() {
        let (_dir, server) = test_server();
        let entity_id = oneiron::EntityId::now();
        let body = json!({
            "txt": "hydrate deleted needle",
            "spkr": "user",
            "at": 600_u64
        });
        server
            .vault
            .batch()
            .put(
                &entity_id,
                ENTITY_TYPE_TURN,
                oneiron::TimeRange {
                    start: 600,
                    end: 600,
                },
                600,
                &rmp_serde::to_vec_named(&body).expect("encode body"),
            )
            .text(&entity_id, &[("body", "hydrate deleted needle")])
            .commit()
            .expect("seed turn");

        let pack = server
            .vault
            .context_pack()
            .search_text("hydrate deleted needle", 1)
            .run()
            .expect("context pack");
        let entity = pack.results.first().expect("hydrated result");
        let short_ref = format!("{}:{:02x}", entity.short_id, entity.content_hash);

        let (malformed_status, malformed_body) = route_json(
            server.clone(),
            json_request("POST", "/v1/core/hydrate", json!({ "ref": "bad-ref" })),
        )
        .await;
        assert_eq!(malformed_status, StatusCode::BAD_REQUEST);
        assert_error_envelope(&malformed_body, "BAD_REQUEST");

        let (not_found_status, not_found_body) = route_json(
            server.clone(),
            json_request("POST", "/v1/core/hydrate", json!({ "ref": "tn999:aa" })),
        )
        .await;
        assert_eq!(not_found_status, StatusCode::NOT_FOUND);
        assert_error_envelope(&not_found_body, "NOT_FOUND");

        let empty_id = oneiron::EntityId::now();
        server
            .vault
            .batch()
            .put(
                &empty_id,
                ENTITY_TYPE_TURN,
                oneiron::TimeRange {
                    start: 601,
                    end: 601,
                },
                601,
                b"",
            )
            .text(&empty_id, &[("body", "empty live body needle")])
            .commit()
            .expect("seed empty live turn");
        let empty_pack = server
            .vault
            .context_pack()
            .search_text("empty live body needle", 1)
            .run()
            .expect("empty context pack");
        let empty_entity = empty_pack.results.first().expect("empty live result");
        let empty_short_ref = format!(
            "{}:{:02x}",
            empty_entity.short_id, empty_entity.content_hash
        );
        let (empty_status, empty_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/core/hydrate",
                json!({ "ref": empty_short_ref }),
            ),
        )
        .await;
        assert_eq!(empty_status, StatusCode::OK, "{empty_body:#}");
        assert_eq!(empty_body["status"], Value::from("live"));
        assert_eq!(empty_body["id"], Value::from(empty_id.to_hex()));
        assert_eq!(empty_body["item"]["bodyBytes"], Value::Array(Vec::new()));

        server
            .vault
            .delete_entity_with_reason(&entity_id, oneiron::DeleteReason::UserDelete)
            .expect("soft delete turn");

        let (deleted_status, deleted_body) = route_json(
            server.clone(),
            json_request("POST", "/v1/core/hydrate", json!({ "ref": short_ref })),
        )
        .await;
        assert_eq!(deleted_status, StatusCode::OK);
        assert_eq!(deleted_body["status"], Value::from("deleted"));
        assert_eq!(deleted_body["id"], Value::from(entity_id.to_hex()));
        assert!(
            matches!(
                deleted_body["deletion"]["source"].as_str(),
                Some("pending_tombstone" | "tombstone")
            ),
            "{deleted_body:#}"
        );
        assert_eq!(
            deleted_body["deletion"]["reason"],
            Value::from("user_delete")
        );
        assert_eq!(deleted_body["deletion"]["hard"], Value::from(false));
        assert!(
            deleted_body["deletion"]["deleted_at"].as_u64().is_some(),
            "{deleted_body:#}"
        );
        assert!(
            deleted_body["deletion"]["request_id"].as_str().is_some(),
            "{deleted_body:#}"
        );
        assert!(deleted_body.get("item").is_none());

        let too_many_refs = vec![empty_short_ref.clone(); CORE_MAX_BATCH_ENTITIES + 1];
        let (too_many_status, too_many_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/core/batch/shortId/hydrate",
                json!({ "refs": too_many_refs }),
            ),
        )
        .await;
        assert_eq!(too_many_status, StatusCode::BAD_REQUEST);
        assert_error_envelope(&too_many_body, "BAD_REQUEST");

        let (batch_status, batch_body) = route_json(
            server,
            json_request(
                "POST",
                "/v1/core/batch/shortId/hydrate",
                json!({
                    "refs": [
                        empty_short_ref,
                        short_ref,
                        "bad-ref",
                        "tn999:aa"
                    ]
                }),
            ),
        )
        .await;
        assert_eq!(batch_status, StatusCode::OK, "{batch_body:#}");
        let results = batch_body["results"].as_array().expect("batch results");
        assert_eq!(results.len(), 4);
        assert_eq!(results[0]["outcome"], Value::from("live"));
        assert_eq!(results[0]["result"]["status"], Value::from("live"));
        assert_eq!(results[0]["result"]["id"], Value::from(empty_id.to_hex()));
        assert_eq!(results[1]["outcome"], Value::from("deleted"));
        assert_eq!(results[1]["result"]["status"], Value::from("deleted"));
        assert_eq!(
            results[1]["result"]["deletion"]["reason"],
            Value::from("user_delete")
        );
        assert_eq!(results[2]["outcome"], Value::from("malformed_short_id"));
        assert_eq!(
            results[2]["error"]["kind"],
            Value::from("malformed_short_id")
        );
        assert_eq!(results[3]["outcome"], Value::from("not_found"));
        assert_eq!(results[3]["error"]["kind"], Value::from("not_found"));
    }

    #[tokio::test]
    async fn v1_core_conversation_routes_create_list_and_read_turns() {
        let (_dir, server) = test_server();

        let (conversation_status, conversation_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/core/conversations",
                json!({
                    "learned_at": 700_u64,
                    "occurred_start": 700_u64,
                    "occurred_end": 700_u64,
                    "body": { "name": "Dream session" }
                }),
            ),
        )
        .await;
        assert_eq!(conversation_status, StatusCode::OK);
        let conversation_id = conversation_body["id"]
            .as_str()
            .expect("conversation id")
            .to_owned();

        let (conversations_status, conversations_body) = route_json(
            server.clone(),
            Request::builder()
                .uri("/v1/core/conversations?view=full")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(conversations_status, StatusCode::OK);
        assert_eq!(
            conversations_body["items"][0]["id"],
            Value::from(conversation_id.clone())
        );
        assert_eq!(
            conversations_body["items"][0]["name"],
            Value::from("Dream session")
        );

        let (turn_status, turn_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                &format!("/v1/core/conversations/{conversation_id}/turns"),
                json!({
                    "learned_at": 701_u64,
                    "occurred_start": 701_u64,
                    "occurred_end": 701_u64,
                    "body": {
                        "txt": "conversation turn needle",
                        "spkr": "assistant",
                        "at": 701_u64
                    }
                }),
            ),
        )
        .await;
        assert_eq!(turn_status, StatusCode::OK);
        let turn_id = turn_body["id"].as_str().expect("turn id").to_owned();
        assert_eq!(
            turn_body["item"]["txt"],
            Value::from("conversation turn needle")
        );

        let (turns_status, turns_body) = route_json(
            server.clone(),
            Request::builder()
                .uri(format!(
                    "/v1/core/conversations/{conversation_id}/turns?view=full"
                ))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(turns_status, StatusCode::OK);
        assert_eq!(turns_body["items"][0]["id"], Value::from(turn_id.clone()));
        assert_eq!(
            turns_body["items"][0]["txt"],
            Value::from("conversation turn needle")
        );

        let (read_status, read_body) = route_json(
            server,
            Request::builder()
                .uri(format!("/v1/core/turns/{turn_id}?view=full"))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(read_status, StatusCode::OK);
        assert_eq!(read_body["txt"], Value::from("conversation turn needle"));
    }

    #[tokio::test]
    async fn v1_core_conversation_turns_honor_after_and_filter_deleted_shells() {
        let (_dir, server) = test_server();

        let (conversation_status, conversation_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/core/conversations",
                json!({
                    "learned_at": 800_u64,
                    "body": { "name": "Cursor session" }
                }),
            ),
        )
        .await;
        assert_eq!(conversation_status, StatusCode::OK);
        let conversation_id = conversation_body["id"]
            .as_str()
            .expect("conversation id")
            .to_owned();

        let mut turn_ids = Vec::new();
        for index in 0..3_u64 {
            let (turn_status, turn_body) = route_json(
                server.clone(),
                json_request(
                    "POST",
                    &format!("/v1/core/conversations/{conversation_id}/turns"),
                    json!({
                        "learned_at": 801_u64 + index,
                        "occurred_start": 801_u64 + index,
                        "occurred_end": 801_u64 + index,
                        "body": {
                            "txt": format!("cursor turn {index}"),
                            "spkr": "assistant",
                            "at": 801_u64 + index
                        }
                    }),
                ),
            )
            .await;
            assert_eq!(turn_status, StatusCode::OK);
            turn_ids.push(turn_body["id"].as_str().expect("turn id").to_owned());
        }

        let (first_page_status, first_page) = route_json(
            server.clone(),
            Request::builder()
                .uri(format!(
                    "/v1/core/conversations/{conversation_id}/turns?limit=1&countMode=none"
                ))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(first_page_status, StatusCode::OK);
        let first_id = first_page["items"][0]["id"]
            .as_str()
            .expect("first page id")
            .to_owned();
        assert_eq!(first_page["nextCursor"], Value::from(first_id.clone()));

        let (second_page_status, second_page) = route_json(
            server.clone(),
            Request::builder()
                .uri(format!(
                    "/v1/core/conversations/{conversation_id}/turns?limit=1&countMode=none&after={first_id}"
                ))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(second_page_status, StatusCode::OK);
        assert_ne!(second_page["items"][0]["id"], Value::from(first_id.clone()));

        let deleted_id = oneiron::EntityId::from_hex(&turn_ids[1]).expect("turn id parses");
        server
            .vault
            .delete_entity_with_reason(&deleted_id, oneiron::DeleteReason::UserDelete)
            .expect("soft delete turn");

        let (deleted_gap_status, deleted_gap_page) = route_json(
            server.clone(),
            Request::builder()
                .uri(format!(
                    "/v1/core/conversations/{conversation_id}/turns?limit=1&countMode=none"
                ))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(deleted_gap_status, StatusCode::OK);
        let deleted_gap_first = deleted_gap_page["items"][0]["id"]
            .as_str()
            .expect("deleted gap first id")
            .to_owned();
        assert_ne!(deleted_gap_first, turn_ids[1]);
        assert_eq!(
            deleted_gap_page["nextCursor"],
            Value::from(deleted_gap_first.clone())
        );

        let (after_deleted_gap_status, after_deleted_gap_page) = route_json(
            server.clone(),
            Request::builder()
                .uri(format!(
                    "/v1/core/conversations/{conversation_id}/turns?limit=1&countMode=none&after={deleted_gap_first}"
                ))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(after_deleted_gap_status, StatusCode::OK);
        let after_deleted_gap_id = after_deleted_gap_page["items"][0]["id"]
            .as_str()
            .expect("after deleted gap id");
        assert_ne!(after_deleted_gap_id, deleted_gap_first);
        assert_ne!(after_deleted_gap_id, turn_ids[1]);

        let (filtered_status, filtered_body) = route_json(
            server,
            Request::builder()
                .uri(format!(
                    "/v1/core/conversations/{conversation_id}/turns?view=full&countMode=exact"
                ))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(filtered_status, StatusCode::OK);
        let listed_ids: Vec<&str> = filtered_body["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| item["id"].as_str().expect("item id"))
            .collect();
        assert_eq!(listed_ids.len(), 2);
        assert!(!listed_ids.contains(&turn_ids[1].as_str()));
        assert_eq!(filtered_body["meta"]["total"], Value::from(2));
    }

    #[tokio::test]
    async fn v1_core_turn_create_maps_childof_constraints_to_invalid_state() {
        let (_dir, server) = test_server();

        let create_conversation = |name: &str| {
            json_request(
                "POST",
                "/v1/core/conversations",
                json!({
                    "body": { "name": name }
                }),
            )
        };
        let (first_status, first_body) =
            route_json(server.clone(), create_conversation("first")).await;
        assert_eq!(first_status, StatusCode::OK);
        let first_conversation = first_body["id"].as_str().expect("first id").to_owned();
        let (second_status, second_body) =
            route_json(server.clone(), create_conversation("second")).await;
        assert_eq!(second_status, StatusCode::OK);
        let second_conversation = second_body["id"].as_str().expect("second id").to_owned();

        let turn_id = oneiron::EntityId::now().to_hex();
        let turn_body = json!({
            "id": turn_id,
            "body": {
                "txt": "cardinality turn",
                "spkr": "assistant",
                "at": 900_u64
            }
        });
        let (first_turn_status, _) = route_json(
            server.clone(),
            json_request(
                "POST",
                &format!("/v1/core/conversations/{first_conversation}/turns"),
                turn_body.clone(),
            ),
        )
        .await;
        assert_eq!(first_turn_status, StatusCode::OK);

        let (conflict_status, conflict_body) = route_json(
            server,
            json_request(
                "POST",
                &format!("/v1/core/conversations/{second_conversation}/turns"),
                turn_body,
            ),
        )
        .await;
        assert_eq!(conflict_status, StatusCode::CONFLICT);
        assert_error_envelope(&conflict_body, "INVALID_STATE");
    }

    #[tokio::test]
    async fn usage_event_uses_runtime_mode_for_byo_no_debit_boundary() {
        let runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::ByoCloudKey);
        let config = SyncServerConfig {
            allow_unauthenticated: true,
            usage_mode: crate::usage::UsageMode::OneironCloud,
            runtime,
            ..Default::default()
        };
        let (_dir, server) = test_server_with_config(config);
        let payload = json!({
            "tenantId": "tenant-a",
            "vaultId": "vault-a",
            "idempotencyKey": "byo-boundary",
            "source": "oneiron_cloud",
            "eventType": "inference",
            "model": "external-model",
            "tokenCounts": {
                "inputTokens": 1000,
                "outputTokens": 500,
                "cacheReadTokens": 0,
                "cacheWriteTokens": 0
            },
            "costRates": {
                "inputTokenUsdPerMillion": 2.0,
                "outputTokenUsdPerMillion": 4.0,
                "cacheReadTokenUsdPerMillion": 0.0,
                "cacheWriteTokenUsdPerMillion": 0.0
            }
        });

        let response = api_routes(server)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/usage/events")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("usage response body");
        let body: Value = serde_json::from_slice(&body).expect("usage JSON body");
        assert_eq!(body["source"], Value::from("byo"));
        assert_eq!(body["debit"], Value::Null);
        assert_eq!(body["recorded"], Value::from(false));
    }

    #[tokio::test]
    async fn usage_event_honors_legacy_usage_mode_when_runtime_is_default() {
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            allow_unauthenticated: true,
            usage_mode: crate::usage::UsageMode::OneironCloud,
            runtime: crate::runtime::RuntimeConfig::default(),
            ..Default::default()
        });
        let payload = json!({
            "tenantId": "tenant-a",
            "vaultId": "vault-a",
            "idempotencyKey": "legacy-usage-default-runtime",
            "source": "local",
            "eventType": "inference",
            "model": "local-orchestrator-default",
            "tokenCounts": {
                "inputTokens": 1000,
                "outputTokens": 500,
                "cacheReadTokens": 0,
                "cacheWriteTokens": 0
            },
            "costRates": {
                "inputTokenUsdPerMillion": 2.0,
                "outputTokenUsdPerMillion": 4.0,
                "cacheReadTokenUsdPerMillion": 0.0,
                "cacheWriteTokenUsdPerMillion": 0.0
            }
        });

        let response = api_routes(server)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/usage/events")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("usage response body");
        let body: Value = serde_json::from_slice(&body).expect("usage JSON body");
        assert_eq!(body["source"], Value::from("oneiron_cloud"));
        assert_eq!(body["recorded"], Value::from(true));
        assert!(body["debit"].is_object());
    }

    #[tokio::test]
    async fn usage_event_rejects_mixed_runtime_without_model_discriminator() {
        let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::LocalFree);
        runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
            RuntimeRole::Orchestrator,
            crate::runtime::RuntimeRoleTargetOverride {
                mode: Some(RuntimeMode::OneironCloud),
                provider_kind: None,
                model: Some("hosted-orchestrator".to_owned()),
            },
        ));
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            allow_unauthenticated: true,
            runtime,
            ..Default::default()
        });
        let payload = json!({
            "tenantId": "tenant-a",
            "vaultId": "vault-a",
            "idempotencyKey": "ambiguous-mixed-route",
            "source": "oneiron_cloud",
            "eventType": "inference",
            "tokenCounts": {
                "inputTokens": 1000,
                "outputTokens": 500,
                "cacheReadTokens": 0,
                "cacheWriteTokens": 0
            },
            "costRates": {
                "inputTokenUsdPerMillion": 2.0,
                "outputTokenUsdPerMillion": 4.0,
                "cacheReadTokenUsdPerMillion": 0.0,
                "cacheWriteTokenUsdPerMillion": 0.0
            }
        });

        let response = api_routes(server)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/usage/events")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("usage response body");
        let body: Value = serde_json::from_slice(&body).expect("ApiError JSON body");
        assert_eq!(body["code"], Value::from("BAD_REQUEST"));
        assert_eq!(body["details"]["field"], Value::from("model"));
    }

    #[tokio::test]
    async fn usage_event_uses_unanimous_hosted_routes_without_model_discriminator() {
        let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::LocalFree);
        for role in RuntimeRole::ALL {
            runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
                role,
                crate::runtime::RuntimeRoleTargetOverride {
                    mode: Some(RuntimeMode::OneironCloud),
                    provider_kind: None,
                    model: Some(format!("hosted-{role}")),
                },
            ));
        }
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            allow_unauthenticated: true,
            runtime,
            ..Default::default()
        });
        let payload = json!({
            "tenantId": "tenant-a",
            "vaultId": "vault-a",
            "idempotencyKey": "unmodeled-hosted-routes",
            "source": "local",
            "eventType": "inference",
            "tokenCounts": {
                "inputTokens": 1000,
                "outputTokens": 500,
                "cacheReadTokens": 0,
                "cacheWriteTokens": 0
            },
            "costRates": {
                "inputTokenUsdPerMillion": 2.0,
                "outputTokenUsdPerMillion": 4.0,
                "cacheReadTokenUsdPerMillion": 0.0,
                "cacheWriteTokenUsdPerMillion": 0.0
            }
        });

        let response = api_routes(server)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/usage/events")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("usage response body");
        let body: Value = serde_json::from_slice(&body).expect("usage JSON body");
        assert_eq!(body["source"], Value::from("oneiron_cloud"));
        assert_eq!(body["recorded"], Value::from(true));
        assert!(body["debit"].is_object());
    }

    #[tokio::test]
    async fn usage_event_accepts_all_unmetered_runtime_mix_without_model_discriminator() {
        let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::LocalFree);
        runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
            RuntimeRole::Orchestrator,
            crate::runtime::RuntimeRoleTargetOverride::mode(RuntimeMode::ByoCloudKey),
        ));
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            allow_unauthenticated: true,
            runtime,
            ..Default::default()
        });
        let payload = json!({
            "tenantId": "tenant-a",
            "vaultId": "vault-a",
            "idempotencyKey": "unmodeled-unmetered-routes",
            "source": "oneiron_cloud",
            "eventType": "inference",
            "tokenCounts": {
                "inputTokens": 1000,
                "outputTokens": 500,
                "cacheReadTokens": 0,
                "cacheWriteTokens": 0
            },
            "costRates": {
                "inputTokenUsdPerMillion": 2.0,
                "outputTokenUsdPerMillion": 4.0,
                "cacheReadTokenUsdPerMillion": 0.0,
                "cacheWriteTokenUsdPerMillion": 0.0
            }
        });

        let response = api_routes(server)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/usage/events")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("usage response body");
        let body: Value = serde_json::from_slice(&body).expect("usage JSON body");
        assert_eq!(body["recorded"], Value::from(false));
        assert_eq!(body["debit"], Value::Null);
    }

    #[tokio::test]
    async fn usage_event_uses_matching_hosted_route_for_debit_boundary() {
        let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::LocalFree);
        runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
            RuntimeRole::Orchestrator,
            crate::runtime::RuntimeRoleTargetOverride {
                mode: Some(RuntimeMode::OneironCloud),
                provider_kind: None,
                model: Some("hosted-orchestrator".to_owned()),
            },
        ));
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            allow_unauthenticated: true,
            runtime,
            ..Default::default()
        });
        let payload = json!({
            "tenantId": "tenant-a",
            "vaultId": "vault-a",
            "idempotencyKey": "hosted-route-boundary",
            "source": "local",
            "eventType": "inference",
            "model": "hosted-orchestrator",
            "tokenCounts": {
                "inputTokens": 1000,
                "outputTokens": 500,
                "cacheReadTokens": 0,
                "cacheWriteTokens": 0
            },
            "costRates": {
                "inputTokenUsdPerMillion": 2.0,
                "outputTokenUsdPerMillion": 4.0,
                "cacheReadTokenUsdPerMillion": 0.0,
                "cacheWriteTokenUsdPerMillion": 0.0
            }
        });

        let response = api_routes(server)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/usage/events")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("usage response body");
        let body: Value = serde_json::from_slice(&body).expect("usage JSON body");
        assert_eq!(body["source"], Value::from("oneiron_cloud"));
        assert_eq!(body["recorded"], Value::from(true));
        assert!(body["debit"].is_object());
    }

    #[tokio::test]
    async fn usage_event_uses_matching_local_route_for_no_debit_boundary() {
        let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::OneironCloud);
        runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
            RuntimeRole::Subagent,
            crate::runtime::RuntimeRoleTargetOverride {
                mode: Some(RuntimeMode::LocalFree),
                provider_kind: None,
                model: Some("local-subagent".to_owned()),
            },
        ));
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            allow_unauthenticated: true,
            runtime,
            ..Default::default()
        });
        let payload = json!({
            "tenantId": "tenant-a",
            "vaultId": "vault-a",
            "idempotencyKey": "local-route-boundary",
            "source": "oneiron_cloud",
            "eventType": "inference",
            "model": "local-subagent",
            "tokenCounts": {
                "inputTokens": 1000,
                "outputTokens": 500,
                "cacheReadTokens": 0,
                "cacheWriteTokens": 0
            },
            "costRates": {
                "inputTokenUsdPerMillion": 2.0,
                "outputTokenUsdPerMillion": 4.0,
                "cacheReadTokenUsdPerMillion": 0.0,
                "cacheWriteTokenUsdPerMillion": 0.0
            }
        });

        let response = api_routes(server)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/usage/events")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("usage response body");
        let body: Value = serde_json::from_slice(&body).expect("usage JSON body");
        assert_eq!(body["source"], Value::from("local"));
        assert_eq!(body["recorded"], Value::from(false));
        assert_eq!(body["debit"], Value::Null);
    }

    #[tokio::test]
    async fn usage_event_rejects_unavailable_model_route_match_before_debiting() {
        let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::OneironCloud);
        runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
            RuntimeRole::Orchestrator,
            crate::runtime::RuntimeRoleTargetOverride::target(
                RuntimeProviderKind::Local,
                "unavailable-hosted-model",
            ),
        ));
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            allow_unauthenticated: true,
            runtime,
            ..Default::default()
        });
        let payload = json!({
            "tenantId": "tenant-a",
            "vaultId": "vault-a",
            "idempotencyKey": "unavailable-model-route",
            "source": "oneiron_cloud",
            "eventType": "inference",
            "model": "unavailable-hosted-model",
            "tokenCounts": {
                "inputTokens": 1000,
                "outputTokens": 500,
                "cacheReadTokens": 0,
                "cacheWriteTokens": 0
            },
            "costRates": {
                "inputTokenUsdPerMillion": 2.0,
                "outputTokenUsdPerMillion": 4.0,
                "cacheReadTokenUsdPerMillion": 0.0,
                "cacheWriteTokenUsdPerMillion": 0.0
            }
        });

        let response = api_routes(server)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/usage/events")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("usage response body");
        let body: Value = serde_json::from_slice(&body).expect("ApiError JSON body");
        assert_eq!(body["code"], Value::from("BAD_REQUEST"));
        assert_eq!(body["details"]["field"], Value::from("model"));
    }

    #[tokio::test]
    async fn usage_event_rejects_unmodeled_unavailable_routes_before_debiting() {
        let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::OneironCloud);
        runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
            RuntimeRole::Orchestrator,
            crate::runtime::RuntimeRoleTargetOverride::target(
                RuntimeProviderKind::Local,
                "unavailable-hosted-model",
            ),
        ));
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            allow_unauthenticated: true,
            runtime,
            ..Default::default()
        });
        let payload = json!({
            "tenantId": "tenant-a",
            "vaultId": "vault-a",
            "idempotencyKey": "unmodeled-unavailable-route",
            "source": "oneiron_cloud",
            "eventType": "inference",
            "tokenCounts": {
                "inputTokens": 1000,
                "outputTokens": 500,
                "cacheReadTokens": 0,
                "cacheWriteTokens": 0
            },
            "costRates": {
                "inputTokenUsdPerMillion": 2.0,
                "outputTokenUsdPerMillion": 4.0,
                "cacheReadTokenUsdPerMillion": 0.0,
                "cacheWriteTokenUsdPerMillion": 0.0
            }
        });

        let response = api_routes(server)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/usage/events")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("usage response body");
        let body: Value = serde_json::from_slice(&body).expect("ApiError JSON body");
        assert_eq!(body["code"], Value::from("BAD_REQUEST"));
        assert_eq!(body["details"]["field"], Value::from("model"));
    }

    #[tokio::test]
    async fn usage_event_accepts_duplicate_unmetered_model_matches() {
        let mut runtime = crate::runtime::RuntimeConfig::for_mode(RuntimeMode::OneironCloud);
        runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_byo_key_env(
            Some("PATH".to_owned()),
        ));
        for (role, mode) in [
            (RuntimeRole::Orchestrator, RuntimeMode::LocalFree),
            (RuntimeRole::Subagent, RuntimeMode::ByoCloudKey),
        ] {
            runtime.apply_override(crate::runtime::RuntimeConfigOverride::with_role_override(
                role,
                crate::runtime::RuntimeRoleTargetOverride {
                    mode: Some(mode),
                    provider_kind: None,
                    model: Some("shared-unmetered-model".to_owned()),
                },
            ));
        }
        let (_dir, server) = test_server_with_config(SyncServerConfig {
            allow_unauthenticated: true,
            runtime,
            ..Default::default()
        });
        let payload = json!({
            "tenantId": "tenant-a",
            "vaultId": "vault-a",
            "idempotencyKey": "duplicate-unmetered-model",
            "source": "oneiron_cloud",
            "eventType": "inference",
            "model": "shared-unmetered-model",
            "tokenCounts": {
                "inputTokens": 1000,
                "outputTokens": 500,
                "cacheReadTokens": 0,
                "cacheWriteTokens": 0
            },
            "costRates": {
                "inputTokenUsdPerMillion": 2.0,
                "outputTokenUsdPerMillion": 4.0,
                "cacheReadTokenUsdPerMillion": 0.0,
                "cacheWriteTokenUsdPerMillion": 0.0
            }
        });

        let response = api_routes(server)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/usage/events")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("usage response body");
        let body: Value = serde_json::from_slice(&body).expect("usage JSON body");
        assert_eq!(body["recorded"], Value::from(false));
        assert_eq!(body["debit"], Value::Null);
    }

    #[tokio::test]
    async fn consumer_top_up_route_is_idempotent() {
        let (_dir, server) = test_server_with_usage_mode(crate::usage::UsageMode::OneironCloud);

        let (first_status, first) = top_up_route(server.clone(), "top-up-idem", 10.0).await;
        let (second_status, second) = top_up_route(server.clone(), "top-up-idem", 10.0).await;
        let (usage_status, usage) = route_json(
            server,
            Request::builder()
                .uri("/v1/consumer/usage?tenantId=tenant-a")
                .body(Body::empty())
                .expect("request"),
        )
        .await;

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(usage_status, StatusCode::OK);
        assert_eq!(first["recorded"], Value::from(true));
        assert_eq!(first["replayed"], Value::from(false));
        assert_eq!(second["recorded"], Value::from(false));
        assert_eq!(second["replayed"], Value::from(true));
        assert_eq!(first["topUp"], second["topUp"]);
        assert_eq!(
            usage["allowance"]["allowanceCreditUnits"],
            Value::from(10.0)
        );
        assert_eq!(
            usage["allowance"]["remainingCreditUnits"],
            Value::from(10.0)
        );
    }

    #[tokio::test]
    async fn consumer_top_up_route_with_http_idempotency_header_reaches_ledger_replay() {
        let (_dir, server) = test_server_with_usage_mode(crate::usage::UsageMode::OneironCloud);
        let top_up = json!({
            "tenantId": "tenant-a",
            "idempotencyKey": "top-up-http-idem",
            "creditUnits": 10.0,
        });
        let request = || {
            Request::builder()
                .method("POST")
                .uri("/v1/consumer/top-up")
                .header(CONTENT_TYPE, "application/json")
                .header(
                    crate::idempotency::IDEMPOTENCY_KEY_HEADER,
                    "http-top-up-key",
                )
                .body(Body::from(top_up.to_string()))
                .expect("request")
        };

        let (first_status, first) = route_json(server.clone(), request()).await;
        let (second_status, second) = route_json(server, request()).await;

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(first["recorded"], Value::from(true));
        assert_eq!(first["replayed"], Value::from(false));
        assert_eq!(second["recorded"], Value::from(false));
        assert_eq!(second["replayed"], Value::from(true));
        assert_eq!(first["topUp"], second["topUp"]);
    }

    #[tokio::test]
    async fn consumer_top_up_route_maps_malformed_json_to_api_error() {
        let (_dir, server) = test_server_with_usage_mode(crate::usage::UsageMode::OneironCloud);

        let (status, body) = route_json(
            server,
            Request::builder()
                .method("POST")
                .uri("/v1/consumer/top-up")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from("{"))
                .expect("request"),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], Value::from("BAD_REQUEST"));
        assert_eq!(body["details"]["code"], Value::from("BAD_REQUEST"));
        assert_eq!(body["message"], Value::from("invalid JSON request body"));
    }

    #[tokio::test]
    async fn consumer_top_up_route_rejects_idempotency_conflicts() {
        let (_dir, server) = test_server_with_usage_mode(crate::usage::UsageMode::OneironCloud);

        let (first_status, first) = top_up_route(server.clone(), "top-up-conflict", 10.0).await;
        let (conflict_status, conflict) =
            top_up_route(server.clone(), "top-up-conflict", 11.0).await;
        let (usage_status, usage) = route_json(
            server,
            Request::builder()
                .uri("/v1/consumer/usage?tenantId=tenant-a")
                .body(Body::empty())
                .expect("request"),
        )
        .await;

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(first["recorded"], Value::from(true));
        assert_eq!(conflict_status, StatusCode::CONFLICT);
        assert_eq!(conflict["code"], Value::from("IDEMPOTENCY_REPLAY_CONFLICT"));
        assert_eq!(
            conflict["details"]["idempotencyKey"],
            Value::from("top-up-conflict")
        );
        assert_eq!(
            conflict["suggestions"],
            json!(["Reuse the original top-up request body or send a new JSON idempotencyKey."])
        );
        assert_eq!(usage_status, StatusCode::OK);
        assert_eq!(
            usage["allowance"]["allowanceCreditUnits"],
            Value::from(10.0)
        );
    }

    #[tokio::test]
    async fn consumer_top_up_route_rejects_normalized_zero_credit_units() {
        let (_dir, server) = test_server_with_usage_mode(crate::usage::UsageMode::OneironCloud);

        let (tiny_status, tiny) =
            top_up_route(server.clone(), "tiny-top-up", 0.0000000000001).await;
        let (retry_status, retry) = top_up_route(server, "tiny-top-up", 1.0).await;

        assert_eq!(tiny_status, StatusCode::BAD_REQUEST);
        assert_eq!(tiny["code"], Value::from("BAD_REQUEST"));
        assert_eq!(tiny["details"]["field"], Value::from("creditUnits"));
        assert_eq!(retry_status, StatusCode::OK);
        assert_eq!(retry["recorded"], Value::from(true));
        assert_eq!(retry["topUp"]["creditUnits"], Value::from(1.0));
    }

    #[tokio::test]
    async fn consumer_top_up_route_rejects_non_finite_allowance_balance() {
        let (_dir, server) = test_server_with_usage_mode(crate::usage::UsageMode::OneironCloud);

        let (first_status, first) = top_up_route(server.clone(), "large-top-up-1", 1.0e296).await;
        let (overflow_status, overflow) =
            top_up_route(server.clone(), "large-top-up-2", 1.0e296).await;
        let (usage_status, usage) = route_json(
            server,
            Request::builder()
                .uri("/v1/consumer/usage?tenantId=tenant-a")
                .body(Body::empty())
                .expect("request"),
        )
        .await;

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(first["recorded"], Value::from(true));
        assert_eq!(overflow_status, StatusCode::BAD_REQUEST);
        assert_eq!(overflow["code"], Value::from("BAD_REQUEST"));
        assert_eq!(overflow["details"]["field"], Value::from("creditUnits"));
        assert_eq!(usage_status, StatusCode::OK);
        assert!(
            usage["allowance"]["allowanceCreditUnits"]
                .as_f64()
                .is_some_and(f64::is_finite),
            "allowance should remain finite after rejected top-up: {usage:?}"
        );
    }

    #[tokio::test]
    async fn consumer_usage_route_returns_usage_allowance_and_warning_state() {
        let (_dir, server) = test_server_with_usage_mode(crate::usage::UsageMode::OneironCloud);
        let (top_up_status, _) = top_up_route(server.clone(), "summary-top-up", 10.0).await;
        let (record_status, _) =
            record_usage_event_route(server.clone(), "summary-usage", 0.08).await;
        let (usage_status, usage) = route_json(
            server,
            Request::builder()
                .uri("/v1/consumer/usage?tenantId=tenant-a")
                .body(Body::empty())
                .expect("request"),
        )
        .await;

        assert_eq!(top_up_status, StatusCode::OK);
        assert_eq!(record_status, StatusCode::OK);
        assert_eq!(usage_status, StatusCode::OK);
        assert_eq!(usage["tenantId"], Value::from("tenant-a"));
        assert_eq!(usage["mode"], Value::from("oneiron_cloud"));
        assert_eq!(usage["counters"]["eventCount"], Value::from(1_u64));
        assert_eq!(
            usage["allowance"]["allowanceCreditUnits"],
            Value::from(10.0)
        );
        assert_eq!(usage["allowance"]["usedCreditUnits"], Value::from(8.0));
        assert_eq!(usage["allowance"]["remainingCreditUnits"], Value::from(2.0));
        assert_eq!(
            usage["allowance"]["warning"]["level"],
            Value::from("notice")
        );
        assert_eq!(usage["allowance"]["warning"]["usedRatio"], Value::from(0.8));
        assert_eq!(
            usage["allowance"]["warning"]["triggered"],
            Value::from(true)
        );
    }

    #[tokio::test]
    async fn consumer_vault_scoped_usage_uses_tenant_allowance_burn_down() {
        let (_dir, server) = test_server_with_usage_mode(crate::usage::UsageMode::OneironCloud);
        let (top_up_status, _) = top_up_route(server.clone(), "vault-scope-top-up", 10.0).await;
        let (vault_a_status, _) =
            record_usage_event_for_vault_route(server.clone(), "vault-a-usage", "vault-a", 0.08)
                .await;
        let (vault_b_status, _) =
            record_usage_event_for_vault_route(server.clone(), "vault-b-usage", "vault-b", 0.015)
                .await;
        let (usage_status, usage) = route_json(
            server.clone(),
            Request::builder()
                .uri("/v1/consumer/usage?tenantId=tenant-a&vaultId=vault-a")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        let (details_status, details) = route_json(
            server,
            Request::builder()
                .uri("/v1/consumer/usage/details?tenantId=tenant-a&vaultId=vault-a")
                .body(Body::empty())
                .expect("request"),
        )
        .await;

        assert_eq!(top_up_status, StatusCode::OK);
        assert_eq!(vault_a_status, StatusCode::OK);
        assert_eq!(vault_b_status, StatusCode::OK);
        assert_eq!(usage_status, StatusCode::OK);
        assert_eq!(details_status, StatusCode::OK);
        assert_eq!(usage["vaultId"], Value::from("vault-a"));
        assert_eq!(usage["counters"]["creditUnits"], Value::from(8.0));
        assert_eq!(usage["allowance"]["usedCreditUnits"], Value::from(9.5));
        assert_eq!(usage["allowance"]["remainingCreditUnits"], Value::from(0.5));
        assert_eq!(
            usage["allowance"]["warning"]["level"],
            Value::from("critical")
        );
        assert_eq!(
            usage["allowance"]["warning"]["usedRatio"],
            Value::from(0.95)
        );
        assert_eq!(
            details["usage"]["counters"]["creditUnits"],
            Value::from(8.0)
        );
        assert_eq!(
            details["usage"]["allowance"]["usedCreditUnits"],
            Value::from(9.5)
        );
        assert_eq!(
            details["usage"]["allowance"]["warning"]["level"],
            Value::from("critical")
        );
        assert_eq!(
            details["agents"]["agent-a"]["eventCount"],
            Value::from(1_u64)
        );
    }

    #[tokio::test]
    async fn consumer_usage_details_route_returns_breakdowns() {
        let (_dir, server) = test_server_with_usage_mode(crate::usage::UsageMode::OneironCloud);
        let (top_up_status, _) = top_up_route(server.clone(), "details-top-up", 100.0).await;
        let (record_status, _) =
            record_usage_event_route(server.clone(), "details-usage", 0.05).await;
        let (details_status, details) = route_json(
            server,
            Request::builder()
                .uri("/v1/consumer/usage/details?tenantId=tenant-a&vaultId=vault-a")
                .body(Body::empty())
                .expect("request"),
        )
        .await;

        assert_eq!(top_up_status, StatusCode::OK);
        assert_eq!(record_status, StatusCode::OK);
        assert_eq!(details_status, StatusCode::OK);
        assert_eq!(details["usage"]["vaultId"], Value::from("vault-a"));
        assert_eq!(
            details["usage"]["counters"]["creditUnits"],
            Value::from(5.0)
        );
        assert_eq!(
            details["agents"]["agent-a"]["eventCount"],
            Value::from(1_u64)
        );
        assert_eq!(
            details["models"]["model-a"]["creditUnits"],
            Value::from(5.0)
        );
        assert_eq!(
            details["services"]["inference"]["costUsd"],
            Value::from(0.05)
        );
    }

    #[tokio::test]
    async fn consumer_usage_route_reports_allowance_warning_thresholds() {
        for (used_credit_units, expected_level, expected_triggered, expected_threshold) in [
            (7.0, "none", false, 0.8),
            (8.0, "notice", true, 0.8),
            (9.5, "critical", true, 0.95),
            (10.0, "exhausted", true, 1.0),
        ] {
            let (_dir, server) = test_server_with_usage_mode(crate::usage::UsageMode::OneironCloud);
            let (top_up_status, _) = top_up_route(server.clone(), "threshold-top-up", 10.0).await;
            let (record_status, _) = record_usage_event_route(
                server.clone(),
                "threshold-usage",
                used_credit_units * crate::usage::CREDIT_UNIT_USD,
            )
            .await;
            let (usage_status, usage) = route_json(
                server,
                Request::builder()
                    .uri("/v1/consumer/usage?tenantId=tenant-a")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await;

            assert_eq!(top_up_status, StatusCode::OK);
            assert_eq!(record_status, StatusCode::OK);
            assert_eq!(usage_status, StatusCode::OK);
            assert_eq!(
                usage["allowance"]["warning"]["level"],
                Value::from(expected_level),
                "used credit units: {used_credit_units}"
            );
            assert_eq!(
                usage["allowance"]["warning"]["triggered"],
                Value::from(expected_triggered),
                "used credit units: {used_credit_units}"
            );
            assert_eq!(
                usage["allowance"]["warning"]["thresholdRatio"],
                Value::from(expected_threshold),
                "used credit units: {used_credit_units}"
            );
        }
    }

    #[tokio::test]
    async fn turn_vad_annotate_route_persists_and_reads_annotations() {
        let (_dir, server) = test_server();
        let turn = oneiron::EntityId::now();
        let message = oneiron::EntityId::now();
        let turn_body = rmp_serde::to_vec_named(&json!({
            "txt": "turn affect",
            "spkr": "user",
            "at": 100_u64,
        }))
        .expect("encode turn body");
        let message_body = rmp_serde::to_vec_named(&json!({
            "txt": "message affect",
            "spkr": "assistant",
            "at": 101_u64,
        }))
        .expect("encode message body");
        server
            .vault
            .put_entity(
                &turn,
                ENTITY_TYPE_TURN,
                oneiron::TimeRange {
                    start: 100,
                    end: 100,
                },
                100,
                &turn_body,
            )
            .expect("put turn");
        server
            .vault
            .put_entity(
                &message,
                ENTITY_TYPE_MESSAGE,
                oneiron::TimeRange {
                    start: 101,
                    end: 101,
                },
                101,
                &message_body,
            )
            .expect("put message");
        server
            .vault
            .put_edge(&message, oneiron::EdgeKind::ChildOf, &turn, 1.0)
            .expect("link message to turn");

        let response = api_routes(server.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/core/turns/annotate")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "turn_id": turn.to_hex(),
                            "source": "model_inference",
                            "vad": {
                                "valence": 0.25,
                                "arousal": 0.5,
                                "dominance": 0.75,
                            },
                            "annotated_at": 200_u64,
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("turn annotate response body");
        let body: Value = serde_json::from_slice(&body).expect("annotation JSON body");
        assert_eq!(body["turn_id"], Value::from(turn.to_hex()));
        assert_eq!(body["message_id"], Value::Null);
        assert_eq!(body["source"], Value::from("model_inference"));
        assert_eq!(
            server
                .vault
                .get_turn_vad_annotation(&turn)
                .unwrap()
                .unwrap()
                .source,
            oneiron::VadAnnotationSource::ModelInference
        );

        let response = api_routes(server.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/core/turns/annotate?turn_id={}", turn.to_hex()))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("turn annotation read response body");
        let body: Value = serde_json::from_slice(&body).expect("annotation JSON body");
        assert_eq!(body["source"], Value::from("model_inference"));

        let response = api_routes(server.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/core/turns/annotate")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "turn_id": turn.to_hex(),
                            "message_id": message.to_hex(),
                            "source": "user_self_report",
                            "vad": {
                                "valence": -0.25,
                                "arousal": 0.25,
                                "dominance": 0.5,
                            },
                            "annotated_at": 201_u64,
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("message annotate response body");
        let body: Value = serde_json::from_slice(&body).expect("annotation JSON body");
        assert_eq!(body["message_id"], Value::from(message.to_hex()));
        assert_eq!(body["source"], Value::from("user_self_report"));
        assert_eq!(
            server
                .vault
                .get_message_vad_annotation(&message)
                .unwrap()
                .unwrap()
                .source,
            oneiron::VadAnnotationSource::UserSelfReport
        );

        let response = api_routes(server.clone())
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/core/turns/annotate?turn_id={}&message_id={}",
                        turn.to_hex(),
                        message.to_hex()
                    ))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("message annotation read response body");
        let body: Value = serde_json::from_slice(&body).expect("annotation JSON body");
        assert_eq!(body["turn_id"], Value::from(turn.to_hex()));
        assert_eq!(body["message_id"], Value::from(message.to_hex()));
        assert_eq!(body["source"], Value::from("user_self_report"));
        assert_eq!(body["vad"]["valence"], Value::from(-0.25));
        assert_eq!(body["vad"]["arousal"], Value::from(0.25));
        assert_eq!(body["vad"]["dominance"], Value::from(0.5));
        assert_eq!(body["annotated_at"], Value::from(201_u64));
    }

    #[tokio::test]
    async fn turn_vad_annotate_route_rejects_message_outside_supplied_turn() {
        let (_dir, server) = test_server();
        let requested_turn = oneiron::EntityId::now();
        let actual_turn = oneiron::EntityId::now();
        let message = oneiron::EntityId::now();
        let body = rmp_serde::to_vec_named(&json!({"txt": "affect"})).expect("encode body");

        server
            .vault
            .put_entity(
                &requested_turn,
                ENTITY_TYPE_TURN,
                oneiron::TimeRange {
                    start: 100,
                    end: 100,
                },
                100,
                &body,
            )
            .expect("put requested turn");
        server
            .vault
            .put_entity(
                &actual_turn,
                ENTITY_TYPE_TURN,
                oneiron::TimeRange {
                    start: 101,
                    end: 101,
                },
                101,
                &body,
            )
            .expect("put actual turn");
        server
            .vault
            .put_entity(
                &message,
                ENTITY_TYPE_MESSAGE,
                oneiron::TimeRange {
                    start: 102,
                    end: 102,
                },
                102,
                &body,
            )
            .expect("put message");
        server
            .vault
            .put_edge(&message, oneiron::EdgeKind::ChildOf, &actual_turn, 1.0)
            .expect("link message to different turn");

        let response = api_routes(server.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/core/turns/annotate")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "turn_id": requested_turn.to_hex(),
                            "message_id": message.to_hex(),
                            "source": "model_inference",
                            "vad": {
                                "valence": 0.1,
                                "arousal": 0.2,
                                "dominance": 0.3,
                            },
                            "annotated_at": 250_u64,
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("mismatch response body");
        let body: Value = serde_json::from_slice(&body).expect("ApiError JSON body");
        assert_error_envelope(&body, "BAD_REQUEST");
        assert_eq!(
            error_envelope(&body)["details"]["field"],
            Value::from("message_id")
        );
        assert_eq!(
            server.vault.get_message_vad_annotation(&message).unwrap(),
            None
        );

        let seeded = oneiron::VadAnnotation::new(
            oneiron::Vad {
                valence: 0.1,
                arousal: 0.2,
                dominance: 0.3,
            },
            oneiron::VadAnnotationSource::ModelInference,
            251,
        )
        .expect("annotation");
        server
            .vault
            .annotate_message_vad(&message, seeded)
            .expect("seed message annotation");

        let response = api_routes(server.clone())
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/core/turns/annotate?turn_id={}&message_id={}",
                        requested_turn.to_hex(),
                        message.to_hex()
                    ))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("mismatch read response body");
        let body: Value = serde_json::from_slice(&body).expect("ApiError JSON body");
        assert_error_envelope(&body, "BAD_REQUEST");
        assert_eq!(
            error_envelope(&body)["details"]["field"],
            Value::from("message_id")
        );
    }

    #[tokio::test]
    async fn turn_vad_annotate_route_rejects_invalid_vad() {
        let (_dir, server) = test_server();
        let turn = oneiron::EntityId::now();
        let turn_body = rmp_serde::to_vec_named(&json!({
            "txt": "invalid turn affect",
        }))
        .expect("encode turn body");
        server
            .vault
            .put_entity(
                &turn,
                ENTITY_TYPE_TURN,
                oneiron::TimeRange {
                    start: 100,
                    end: 100,
                },
                100,
                &turn_body,
            )
            .expect("put turn");

        let response = api_routes(server.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/core/turns/annotate")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "turn_id": turn.to_hex(),
                            "source": "user_self_report",
                            "vad": {
                                "valence": 0.0,
                                "arousal": -0.1,
                                "dominance": 0.5,
                            },
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("invalid VAD response body");
        let body: Value = serde_json::from_slice(&body).expect("ApiError JSON body");
        assert_error_envelope(&body, "BAD_REQUEST");
        assert_eq!(
            error_envelope(&body)["details"]["field"],
            Value::from("vad")
        );
        assert_eq!(server.vault.get_turn_vad_annotation(&turn).unwrap(), None);
    }

    #[test]
    fn vad_annotation_core_error_maps_gate_rejection_to_invalid_state() {
        let error = vad_annotation_core_error(oneiron::Error::GateWriteRejected {
            outcome: "pending",
            reason_codes: vec!["gate.pending.source_trust"],
        });

        assert_eq!(error.status(), StatusCode::CONFLICT);
        assert_eq!(error.code(), ErrorCode::InvalidState);
        assert_eq!(
            error.details(),
            &ApiErrorDetails::InvalidState {
                state: Some("gate_write_rejected:pending:gate.pending.source_trust".to_owned()),
            }
        );
        assert!(
            error.message().contains("gate.pending.source_trust"),
            "message should expose the stable Gate reason code"
        );
    }

    #[test]
    fn core_engine_error_maps_temporal_parse_errors_to_bad_request() {
        let error = core_engine_error(
            "core query failed",
            oneiron::Error::InvalidTemporalExpression(
                oneiron::types::TemporalExpressionParseError::Unsupported {
                    expression: "last friday".to_owned(),
                },
            ),
        );

        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error.code(), ErrorCode::BadRequest);
        assert!(
            error.message().contains("unsupported temporal expression"),
            "message should expose the temporal parse failure"
        );
    }

    #[tokio::test]
    async fn context_pack_route_returns_pack_evidence_and_records_telemetry() {
        let (_dir, server) = test_server();
        let (batch_status, batch_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/core/batch",
                json!({
                    "entities": [{
                        "entity_type": ENTITY_TYPE_TURN,
                        "learned_at": 500_u64,
                        "occurred_start": 500_u64,
                        "occurred_end": 500_u64,
                        "body": {
                            "txt": "public context pack evidence needle",
                            "spkr": "user",
                            "at": 500_u64
                        },
                        "text": [{ "field": "body", "value": "public context pack evidence needle" }]
                    }]
                }),
            ),
        )
        .await;
        assert_eq!(batch_status, StatusCode::OK);
        let id = batch_body["entities"][0]["id"]
            .as_str()
            .expect("written id")
            .to_owned();

        let (status, body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/api/context-pack",
                json!({
                    "query": "evidence needle",
                    "limit": 5,
                    "depth": { "edge_hop": 1, "max_neighbors": 5 },
                    "policy": {
                        "hydrate": true,
                        "include_edges": true,
                        "view": "full",
                        "boost_confidence": true
                    },
                    "time": { "occurred_start": 500_u64, "occurred_end": 500_u64 },
                    "budget": {
                        "max_item_tokens": 64,
                        "retrieval": {
                            "claims": 0,
                            "turns": 1,
                            "summaries": 0,
                            "facets": 0,
                            "other": 0,
                            "selected_edges": 5
                        }
                    }
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["results"][0]["id"], Value::from(id.clone()));
        assert_eq!(body["state"]["kind"], Value::from("ok"));
        assert_eq!(body["evidence"]["telemetry_persisted"], Value::from(true));
        assert_eq!(
            body["evidence"]["result_ids"],
            Value::Array(vec![Value::from(id.clone())])
        );
        assert_eq!(body["evidence"]["scores"][0]["result_id"], Value::from(id));
        assert_eq!(
            body["evidence"]["scores"][0]["components"][0]["signal"],
            Value::from("text")
        );

        let runs = server.vault.retrieval_runs(1).expect("retrieval runs");
        assert_eq!(runs.len(), 1);
        assert_eq!(
            runs[0].run_id.to_hex(),
            body["evidence"]["retrieval_run_id"]
        );
        assert_eq!(runs[0].action, oneiron::RetrievalAction::ContextPack);
    }

    #[tokio::test]
    async fn context_pack_route_projects_json_response_controls() {
        let (_dir, server) = test_server();
        let long_text = format!("projection budget needle {}", "x".repeat(800));
        let (batch_status, batch_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/v1/core/batch",
                json!({
                    "entities": [{
                        "entity_type": ENTITY_TYPE_TURN,
                        "learned_at": 510_u64,
                        "occurred_start": 510_u64,
                        "occurred_end": 510_u64,
                        "body": {
                            "txt": long_text,
                            "spkr": "user",
                            "at": 510_u64,
                            "sess": "session-alpha",
                            "debug": "private"
                        },
                        "text": [{ "field": "body", "value": "projection budget needle" }]
                    }]
                }),
            ),
        )
        .await;
        assert_eq!(batch_status, StatusCode::OK);
        let id = batch_body["entities"][0]["id"]
            .as_str()
            .expect("written id")
            .to_owned();

        let (summary_status, summary_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/api/context-pack",
                json!({
                    "query": "projection budget needle",
                    "limit": 5,
                    "policy": { "view": "summary" }
                }),
            ),
        )
        .await;
        assert_eq!(summary_status, StatusCode::OK);
        assert_eq!(summary_body["results"][0]["id"], Value::from(id.clone()));
        let fields = summary_body["results"][0]["fields"]
            .as_object()
            .expect("projected fields");
        assert!(fields.contains_key("txt"));
        assert!(!fields.contains_key("spkr"));
        assert!(!fields.contains_key("at"));
        assert!(!fields.contains_key("sess"));
        assert!(!fields.contains_key("debug"));

        let (budget_status, budget_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/api/context-pack",
                json!({
                    "query": "projection budget needle",
                    "limit": 5,
                    "policy": { "view": "full" },
                    "maxItemTokens": 48
                }),
            ),
        )
        .await;
        assert_eq!(budget_status, StatusCode::OK);
        assert_eq!(budget_body["results"][0]["id"], Value::from(id.clone()));
        let truncated = budget_body["results"][0]["fields"]["txt"]
            .as_str()
            .expect("truncated text field");
        assert!(truncated.contains("truncated"));
        assert_eq!(
            budget_body["stats"]["items_truncated"]["count"],
            Value::from(1)
        );
        assert_eq!(
            budget_body["evidence"]["result_ids"],
            Value::Array(vec![Value::from(id.clone())])
        );

        let (dropped_status, dropped_body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/api/context-pack",
                json!({
                    "query": "projection budget needle",
                    "limit": 5,
                    "policy": { "view": "full" },
                    "maxItemTokens": 1
                }),
            ),
        )
        .await;
        assert_eq!(dropped_status, StatusCode::OK);
        assert_eq!(dropped_body["results"], Value::Array(Vec::new()));
        assert_eq!(dropped_body["neighbors"], Value::Array(Vec::new()));
        assert_eq!(dropped_body["state"]["kind"], Value::from("missing_data"));
        assert_eq!(
            dropped_body["state"]["reason"],
            Value::from("filter_matched_none")
        );
        assert!(
            dropped_body["state"]["hint"]
                .as_str()
                .is_some_and(|hint| hint.contains("budget.max_item_tokens"))
        );
        assert_eq!(
            dropped_body["empty"]["reason"],
            Value::from("filter_matched_none")
        );
        assert_eq!(
            dropped_body["stats"]["items_dropped"]["count"],
            Value::from(1)
        );
        assert_eq!(
            dropped_body["evidence"]["result_ids"],
            Value::Array(Vec::new())
        );
        assert_eq!(dropped_body["evidence"]["scores"], Value::Array(Vec::new()));

        let runs = server.vault.retrieval_runs(1).expect("retrieval runs");
        assert_eq!(runs.len(), 1);
        assert!(runs[0].result_ids.is_empty());
        assert!(runs[0].score_breakdown.is_empty());
        assert_eq!(runs[0].empty_reason.as_deref(), Some("ItemBudget"));
    }

    #[test]
    fn context_pack_evidence_omits_run_id_without_finalized_telemetry() {
        let (_dir, server) = test_server();
        let evidence =
            core_context_pack_evidence(&server.vault, Some(oneiron::RetrievalRunId::now()))
                .expect("context-pack evidence");

        assert!(!evidence.telemetry_persisted);
        assert_eq!(evidence.retrieval_run_id, None);
        assert!(evidence.result_ids.is_empty());
        assert!(evidence.scores.is_empty());
    }

    #[test]
    fn non_empty_query_trims_and_filters_blank_values() {
        assert_eq!(non_empty_query(None), None);
        assert_eq!(non_empty_query(Some("")), None);
        assert_eq!(non_empty_query(Some("   \n\t  ")), None);
        assert_eq!(
            non_empty_query(Some("  recent decisions  ")),
            Some("recent decisions")
        );
    }

    #[tokio::test]
    async fn context_pack_route_rejects_malformed_controls() {
        let (_dir, server) = test_server();
        let (status, body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/api/context-pack",
                json!({
                    "query": "recent decisions",
                    "depth": { "edge_hop": oneiron::context_pack::MAX_EDGE_HOP + 1 }
                }),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], Value::from("BAD_REQUEST"));
        assert_eq!(body["details"]["field"], Value::from("depth.edge_hop"));
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|message| message.contains("edge_hop")),
            "control error should name the malformed field: {body:?}"
        );

        let (status, body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/api/context-pack",
                json!({
                    "query": "recent decisions",
                    "edge_hop": oneiron::context_pack::MAX_EDGE_HOP + 1
                }),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], Value::from("BAD_REQUEST"));
        assert_eq!(body["details"]["field"], Value::from("edge_hop"));

        let (status, body) = route_json(
            server.clone(),
            json_request(
                "POST",
                "/api/context-pack",
                json!({
                    "query": "recent decisions",
                    "max_neighbors": oneiron::context_pack::MAX_CONTEXT_NEIGHBORS + 1
                }),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], Value::from("BAD_REQUEST"));
        assert_eq!(body["details"]["field"], Value::from("max_neighbors"));

        let (status, body) = route_json(
            server,
            json_request(
                "POST",
                "/api/context-pack",
                json!({
                    "query": "recent decisions",
                    "time": {
                        "since": 300_u64,
                        "learned_start": 100_u64,
                        "learned_end": 200_u64
                    }
                }),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], Value::from("BAD_REQUEST"));
        assert_eq!(body["details"]["field"], Value::from("time.since"));
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|message| message.contains("learned_end")),
            "control error should name the contradictory learned bound: {body:?}"
        );
    }

    #[tokio::test]
    async fn text_search_response_shape_still_deserializes() {
        let (_dir, server) = test_server();

        let response = search_text(
            HeaderMap::new(),
            State(server),
            Ok(Query(TextSearchQuery {
                query: "shape guard".to_owned(),
                limit: 1,
                view: Some(View::Summary),
                count_mode: CountMode::Estimate,
            })),
        )
        .await
        .expect("text search response");

        let body = serde_json::to_vec(&response.0).expect("serialize response");
        let parsed: Value = serde_json::from_slice(&body).expect("deserialize response");
        assert_eq!(parsed["items"], Value::Array(Vec::new()));
        assert_eq!(parsed["meta"]["countMode"], Value::from("estimate"));
    }
}
