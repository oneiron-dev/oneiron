//! HTTP query routes for web dashboard access.
//!
//! These routes provide server-side query capabilities for clients
//! that don't have a local LMDB vault (e.g., web dashboard).
//!
//! Auth: shared secret header for Phase 1.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header::CONTENT_TYPE};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::{Router, middleware};
use oneiron::{
    EdgeKind, ErrorKind, NotificationItem, ResumeBudget, ResumeBundle, SessionContext,
    UnprocessedItem, Vad, VadAnnotation, VadAnnotationSource,
    types::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_TURN},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::config::SyncServerConfig;
use crate::error::{ApiError, ApiErrorDetails, ErrorCode};
use crate::idempotency::{IdempotencyLayerState, idempotency_middleware};
use crate::projection::{self, View};
use crate::protocol::{CountMode, PaginatedResponse, ResponseMeta};
use crate::server::SyncServer;
use crate::skills_pack as skills_pack_artifact;
use crate::usage::{UsageError, UsageEvent, UsageRecordResult, UsageRollup};

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
const CONTEXT_PACK_FEATURE: &str = "context-pack HTTP endpoint";
const EFFECTIVE_AUTH_SCOPES: &[&str] = &[
    "core:discover",
    "vault:read",
    "search:read",
    "entity:read",
    "turns:annotate",
    "companion:resume",
    "usage:read",
    "usage:write",
    "sync:connect",
];
const CAPABILITIES: &[&str] = &[
    "core.discover",
    "health.capabilities",
    "skills_pack.fetch",
    "search.vector",
    "search.text",
    "entity.get",
    "edges.get",
    "turns.annotate",
    "context_pack",
    "companion.resume",
    "lease.revoke",
    "usage.event",
    "usage.rollup",
];
const CAPABILITY_MODES: &[&str] = &["flash", "thinking", "pro", "ultra"];
// ONE-214 is read-only and adds no notification-specific storage. Keep resume
// hydration bounded by returning pending notifications from a latest window.
const RESUME_NOTIFICATION_LIMIT: usize = 128;
const RESUME_NOTIFICATION_SCAN_LIMIT: usize = 4096;

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
        annotate_turn_vad,
        read_turn_vad_annotation,
        context_pack,
        record_usage_event,
        get_usage_rollup,
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
        ApiError,
        ApiErrorDetails,
        ErrorCode,
        VectorSearchQuery,
        SearchResult,
        TextSearchQuery,
        EdgeResult,
        VadPayload,
        TurnVadAnnotationSource,
        TurnVadAnnotateRequest,
        TurnVadAnnotateQuery,
        TurnVadAnnotateResponse,
        LeaseRevokeRequest,
        LeaseRevokeResponse,
        ContextPackRequest,
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
    let mutation_routes = Router::new()
        // owner recovery surface (ONE-1140, OD-8): revoke a lost/stolen
        // device's lease binding (terminal)
        .route("/api/lease/revoke", post(lease_revoke))
        .route("/v1/core/turns/annotate", post(annotate_turn_vad))
        .route_layer(middleware::from_fn_with_state(
            idempotency,
            idempotency_middleware,
        ));

    Router::new()
        .route("/api/openapi.json", get(openapi_json))
        .route("/api/skills/oneiron.skills.md", get(skills_pack))
        .route("/api/health", get(health))
        .route("/api/core/discover", get(discover))
        .route("/api/search/vector", get(search_vector))
        .route("/api/search/text", get(search_text))
        .route("/api/entity/{id}", get(get_entity))
        .route("/api/edges/{id}", get(get_edges))
        .route("/v1/core/turns/annotate", get(read_turn_vad_annotation))
        // context-pack is POST since it takes a complex options body
        .route("/api/context-pack", post(context_pack))
        .route("/api/companion/resume", post(resume))
        .route("/v1/usage/events", post(record_usage_event))
        .route(
            "/v1/usage/tenants/{tenant_id}/rollup",
            get(get_usage_rollup),
        )
        .merge(mutation_routes)
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

    let protected_operations = [
        ("/api/openapi.json", "get"),
        ("/api/skills/oneiron.skills.md", "get"),
        ("/api/core/discover", "get"),
        ("/api/search/vector", "get"),
        ("/api/search/text", "get"),
        ("/api/entity/{id}", "get"),
        ("/api/edges/{id}", "get"),
        ("/v1/core/turns/annotate", "get"),
        ("/v1/core/turns/annotate", "post"),
        ("/api/context-pack", "post"),
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
    })
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

/// Optional selector for a tenant usage rollup.
#[derive(Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
struct UsageRollupQuery {
    /// Vault id to read a per-vault rollup. Omit for the tenant-wide rollup.
    #[schema(example = "vault-a")]
    #[param(example = "vault-a")]
    vault_id: Option<String>,
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
    let result = server
        .usage_ledger
        .record_event(event, server.config.usage_mode)
        .inspect_err(|error| tracing::error!(error = %error, "usage event record failed"))
        .map_err(usage_error)?;
    Ok(Json(result))
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
    if let Some(field) = error.field() {
        return ApiError::bad_request(error.to_string(), Some(field));
    }

    ApiError::internal_server_error("usage ledger persistence failed")
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
            description = "Turn or message entity was not found.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "VAD annotation persistence failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
async fn annotate_turn_vad(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Json(req): Json<TurnVadAnnotateRequest>,
) -> Result<Json<TurnVadAnnotateResponse>, ApiError> {
    check_api_auth(&headers, &server.config)?;
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
            description = "Turn/message entity or VAD annotation was not found.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "VAD annotation read failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
async fn read_turn_vad_annotation(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<TurnVadAnnotateQuery>, QueryRejection>,
) -> Result<Json<TurnVadAnnotateResponse>, ApiError> {
    check_api_auth(&headers, &server.config)?;
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
        return Err(ApiError::not_found("vad_annotation", Some(id)));
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
    match error.kind() {
        ErrorKind::InvalidVad => ApiError::bad_request(error.to_string(), Some("vad")),
        ErrorKind::InvalidEntityType => ApiError::bad_request(error.to_string(), Some("entity")),
        ErrorKind::EntityNotFound => ApiError::not_found("entity", None),
        _ => {
            tracing::error!(error = %error, "VAD annotation operation failed");
            ApiError::internal_server_error("VAD annotation operation failed")
        }
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
    "limit": 10
}))]
#[allow(dead_code)] // Request shape is documented while the HTTP endpoint fails closed.
struct ContextPackRequest {
    /// Optional text retrieval seed for context-pack assembly; omit when the caller only has an embedding vector.
    #[schema(example = "recent decisions about project alpha")]
    query: Option<String>,
    /// Optional embedding vector retrieval seed; omit when the caller only has text.
    #[schema(example = json!([0.12, -0.04, 0.98]))]
    query_vector: Option<Vec<f32>>,
    /// Maximum number of candidate entities to retrieve for the pack. Defaults to `10` when omitted.
    #[serde(default = "default_limit")]
    #[schema(default = default_limit, example = 10)]
    limit: usize,
    /// Per-item token cap for context-pack serialization; 0 disables it.
    #[serde(default, rename = "maxItemTokens", alias = "max_item_tokens")]
    max_item_tokens: usize,
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
            status = 501,
            description = "Context-pack assembly is not implemented; endpoint fails closed instead of returning a placeholder pack.",
            body = ApiError,
            content_type = "application/json",
            example = json!({
                "code": "NOT_IMPLEMENTED",
                "message": "context-pack HTTP endpoint is not implemented",
                "details": { "code": "NOT_IMPLEMENTED" },
                "suggestions": ["Do not treat this response as a successful context pack."]
            })
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
    Json(_req): Json<ContextPackRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_api_auth(&headers, &server.config)?;

    Err(ApiError::not_implemented(CONTEXT_PACK_FEATURE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, header::CONTENT_TYPE};
    use serde_json::Value;
    use tower::ServiceExt;

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
        let dir = tempfile::tempdir().expect("temp vault dir");
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
        let config = SyncServerConfig {
            allow_unauthenticated: true,
            ..Default::default()
        };
        let server = Arc::new(SyncServer::new(vault, config).expect("sync server"));
        (dir, server)
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
            "/v1/core/turns/annotate",
            "/api/context-pack",
            "/api/lease/revoke",
            "/api/health",
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
        let context_pack_responses = spec["paths"]["/api/context-pack"]["post"]["responses"]
            .as_object()
            .expect("context-pack responses object");
        assert!(
            !context_pack_responses.contains_key("200"),
            "context-pack must not document a placeholder success response"
        );
        let context_pack_not_implemented =
            &context_pack_responses["501"]["content"]["application/json"]["example"];
        assert_eq!(
            context_pack_not_implemented["code"],
            Value::from("NOT_IMPLEMENTED"),
            "context-pack must document explicit fail-closed status"
        );
        assert_eq!(
            context_pack_not_implemented.get("status"),
            None,
            "context-pack must not document legacy status: ok placeholder body"
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
        for (path, method) in [
            ("/api/openapi.json", "get"),
            ("/api/skills/oneiron.skills.md", "get"),
            ("/api/core/discover", "get"),
            ("/api/search/vector", "get"),
            ("/api/search/text", "get"),
            ("/api/entity/{id}", "get"),
            ("/api/edges/{id}", "get"),
            ("/v1/core/turns/annotate", "get"),
            ("/v1/core/turns/annotate", "post"),
            ("/api/context-pack", "post"),
            ("/api/lease/revoke", "post"),
        ] {
            assert_eq!(
                spec["paths"][path][method]["security"],
                json!([{ "OneironSecret": [] }]),
                "{method} {path} must require OneironSecret"
            );
        }

        assert!(
            spec["components"]["schemas"].get("ApiError").is_some(),
            "structured ApiError schema must be reusable from components"
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
            "VectorSearchQuery",
            "SearchResult",
            "TextSearchQuery",
            "EdgeResult",
            "VadPayload",
            "TurnVadAnnotateRequest",
            "TurnVadAnnotateQuery",
            "TurnVadAnnotateResponse",
            "LeaseRevokeRequest",
            "LeaseRevokeResponse",
            "ContextPackRequest",
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
        assert_eq!(body["code"], Value::from("BAD_REQUEST"));
        assert_eq!(body["details"]["field"], Value::from("message_id"));
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
        assert_eq!(body["code"], Value::from("BAD_REQUEST"));
        assert_eq!(body["details"]["field"], Value::from("message_id"));
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
        assert_eq!(body["code"], Value::from("BAD_REQUEST"));
        assert_eq!(body["details"]["field"], Value::from("vad"));
        assert_eq!(server.vault.get_turn_vad_annotation(&turn).unwrap(), None);
    }

    #[tokio::test]
    async fn context_pack_route_returns_501_instead_of_placeholder_success() {
        let (_dir, server) = test_server();
        let response = api_routes(server)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/context-pack")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"query":"recent decisions","limit":1,"maxItemTokens":64}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("route response");

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("context-pack response body");
        let body: Value = serde_json::from_slice(&body).expect("ApiError JSON body");
        assert_eq!(body["code"], Value::from("NOT_IMPLEMENTED"));
        assert_eq!(body["details"]["code"], Value::from("NOT_IMPLEMENTED"));
        assert_eq!(
            body.get("status"),
            None,
            "context-pack must not return the legacy status: ok placeholder body"
        );
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|message| message.contains("not implemented")),
            "context-pack message must clearly state not implemented: {body:?}"
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
