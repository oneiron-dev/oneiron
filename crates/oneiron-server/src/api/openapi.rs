use super::ApiDoc;
use super::check_api_auth;
use super::skills_pack_artifact;
use crate::error::ApiError;
use crate::server::SyncServer;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::response::Json;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;
use utoipa::OpenApi;

pub(crate) const SKILL_PACK_NAME: &str = "oneiron-http-memory-api";

pub(crate) const SKILL_PACK_ENDPOINT: &str = "/api/skills/oneiron.skills.md";

pub(crate) const SKILL_PACK_FORMAT: &str = "agentskills.io";

pub(crate) const SKILL_PACK_MIME_TYPE: &str = "text/markdown";

pub(crate) const SKILL_PACK_LAYER_BOUNDARY: &str =
    "skills = how to think about memory; MCP tools = what to call";

pub(crate) const SKILL_PACK_LOAD_HINT: &str = "GET /api/skills/oneiron.skills.md from the same Oneiron HTTP origin before choosing memory search, read, context-pack, discovery, or recovery calls; use MCP tools as the callable layer.";

pub(crate) const SKILL_PACK_RESOLUTION: &str = "Resolve endpoint against the same origin used for /api/core/discover and send the configured x-oneiron-secret; do not resolve the pack against a local working directory.";

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
pub(crate) async fn openapi_json(
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
pub(crate) async fn skills_pack(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Result<impl IntoResponse, ApiError> {
    check_api_auth(&headers, &server.config)?;
    Ok((
        [(CONTENT_TYPE, skills_pack_artifact::MEDIA_TYPE)],
        skills_pack_artifact::CONTENT,
    ))
}

pub(crate) fn openapi_document() -> Value {
    let mut spec = serde_json::to_value(ApiDoc::openapi()).expect("serialize generated OpenAPI");
    merge_error_components(&mut spec);
    add_security_scheme(&mut spec);
    mark_entity_response_as_binary(&mut spec);
    fill_schema_description_gaps(&mut spec);
    spec
}

pub(crate) fn merge_error_components(spec: &mut Value) {
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

pub(crate) fn mark_entity_response_as_binary(spec: &mut Value) {
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

pub(crate) fn fill_schema_description_gaps(spec: &mut Value) {
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
        "CoreContextPackRequest",
        "context_version",
        "Optional context format version. Use v4 to request Eiri Context v4 fields.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackRequest",
        "memory_board",
        "Optional Eiri Context v4 memory-board controls.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackRequest",
        "session_rag",
        "Optional Eiri Context v4 session RAG controls.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackRequest",
        "companion",
        "Optional companion scope for Eiri Context v4 assembly.",
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
        "ContextPackRequest",
        "context_version",
        "Optional context format version. Use v4 to request Eiri Context v4 fields.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRequest",
        "memory_board",
        "Optional Eiri Context v4 memory-board controls.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRequest",
        "session_rag",
        "Optional Eiri Context v4 session RAG controls.",
    );
    set_schema_property_description(
        spec,
        "ContextPackRequest",
        "companion",
        "Optional companion scope for Eiri Context v4 assembly.",
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
        "CoreContextPackResponse",
        "context_version",
        "Optional context format version for v4 response extensions.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackResponse",
        "memory_board",
        "Eiri Context v4 memory-board rows when requested.",
    );
    set_schema_property_description(
        spec,
        "CoreContextPackResponse",
        "session_rag",
        "Eiri Context v4 session RAG state when requested.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriMemoryBoardBudget",
        "claims",
        "Claim row cap.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriMemoryBoardBudget",
        "turns",
        "Turn/message row cap.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriMemoryBoardBudget",
        "summaries",
        "Summary row cap.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriMemoryBoardBudget",
        "facets",
        "Facet row cap.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriMemoryBoardBudget",
        "companions",
        "Companion-register row cap.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriMemoryBoardBudget",
        "other",
        "Row cap for all other entity types.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriCompanionAssembly",
        "caller",
        "Effective caller/session identity used for the v4 board.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriCompanionAssembly",
        "person_ref",
        "Optional person entity id for companion-aware assembly metadata.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriCompanionAssembly",
        "persona_ref",
        "Optional persona entity id for companion-aware assembly metadata.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriMemoryBoardRow",
        "row_index",
        "Zero-based index after stable sorting and slot-budget filtering.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriMemoryBoardRow",
        "slot",
        "Budget slot that owns this row.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriMemoryBoardRow",
        "source",
        "Whether the row came from primary results or neighbors.",
    );
    set_schema_property_description(spec, "CoreEiriMemoryBoardRow", "id", "Hex entity id.");
    set_schema_property_description(
        spec,
        "CoreEiriMemoryBoardRow",
        "short_id",
        "Short id used for compact display.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriMemoryBoardRow",
        "content_hash",
        "One-byte content hash as two lowercase hex digits.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriMemoryBoardRow",
        "entity_type",
        "Numeric entity type byte.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriMemoryBoardRow",
        "asset_ref",
        "Short ref for ASSET and ASSET_TEXT rows. Consumers pass this to the core hydrate resolver.",
    );
    set_schema_property_description(spec, "CoreEiriMemoryBoardRow", "score", "Retrieval score.");
    set_schema_property_description(
        spec,
        "CoreEiriMemoryBoard",
        "version",
        "Context version for this memory-board envelope.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriMemoryBoard",
        "budget",
        "Applied per-slot row budget.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriMemoryBoard",
        "rows",
        "Stable memory-board rows.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriMemoryBoard",
        "companion",
        "Companion assembly metadata when v4 companion controls are present.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriSessionRagState",
        "session_id",
        "Effective v4 session id.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriSessionRagState",
        "revision",
        "Monotonic cursor revision for this session.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriSessionRagState",
        "query_count",
        "Number of context-pack queries observed for this session.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriSessionRagState",
        "last_retrieval_run_id",
        "Last persisted retrieval telemetry run id, when available.",
    );
    set_schema_property_description(
        spec,
        "CoreEiriSessionRagState",
        "last_result_ids",
        "Bounded list of most recent context-pack result ids for this session.",
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

pub(crate) fn set_schema_property_description(
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

pub(crate) fn add_security_scheme(spec: &mut Value) {
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
        ("/v1/core/run-tree", "get"),
        ("/v1/core/run-tree/observe", "get"),
        ("/v1/core/run-tree/intervene", "post"),
        ("/v1/core/memory/{id}/timeline", "get"),
        ("/v1/core/memory/verbs/{verb}", "post"),
        ("/v1/core/outbound/capabilities", "get"),
        ("/v1/core/outbound/capabilities/{connector}", "get"),
        (
            "/v1/core/outbound/capabilities/{connector}/verbs/{verb}",
            "get",
        ),
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
        ("/v1/companion/profiles/{persona_ref}", "post"),
        ("/v1/companion/register/records", "post"),
        ("/v1/companion/register/records/{record_id}", "get"),
        ("/v1/companion/register/records/{record_id}", "post"),
        ("/v1/companion/register/records/{record_id}/retire", "post"),
        (
            "/v1/companion/register/records/{record_id}/end-relationship",
            "post",
        ),
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
