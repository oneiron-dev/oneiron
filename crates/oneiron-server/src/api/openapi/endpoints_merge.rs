//! OpenAPI endpoint wiring and component merges.

use super::*;
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

pub(crate) const SKILL_PACK_RESOLUTION: &str = "Resolve endpoint against the same origin used for /api/core/discover and send the configured bearer credential; do not resolve the pack against a local working directory.";

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
            description = "Missing or invalid bearer credentials.",
            body = ApiError,
            content_type = "application/json",
            example = json!({
                "code": "UNAUTHORIZED",
                "message": "request is not authorized",
                "details": { "code": "UNAUTHORIZED" },
                "suggestions": ["Send Authorization: Bearer credentials and retry."]
            })
        )
    )
)]
pub(crate) async fn openapi_json(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<Value>, ApiError> {
    check_api_auth(&headers, &server)?;
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
            description = "Missing or invalid bearer credentials.",
            body = ApiError,
            content_type = "application/json",
            example = json!({
                "code": "UNAUTHORIZED",
                "message": "request is not authorized",
                "details": { "code": "UNAUTHORIZED" },
                "suggestions": ["Send Authorization: Bearer credentials and retry."]
            })
        )
    )
)]
pub(crate) async fn skills_pack(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Result<impl IntoResponse, ApiError> {
    check_api_auth(&headers, &server)?;
    Ok((
        [(CONTENT_TYPE, skills_pack_artifact::MEDIA_TYPE)],
        skills_pack_artifact::CONTENT,
    ))
}

pub(crate) fn openapi_document() -> Value {
    let mut spec = serde_json::to_value(ApiDoc::openapi()).expect("serialize generated OpenAPI");
    merge_error_components(&mut spec);
    merge_booking_components(&mut spec);
    merge_retrieval_depth_components(&mut spec);
    add_security_scheme(&mut spec);
    mark_entity_response_as_binary(&mut spec);
    fill_schema_description_gaps(&mut spec);
    spec
}

// -------------------------------------------------------------------------
// ONE-1819 [BK-08] booking schemas
//
// The booking wire lives in the engine crate, which carries no OpenAPI
// derive, so the strict schemas are published here instead of duplicated as a
// second set of server-side DTOs. Every operation input schema is the SAME
// builder `crate::mcp::book_tool_schema` uses, so the OpenAPI document, the
// MCP tool schema, and the instructions block cannot describe different
// shapes for the same operation.
// -------------------------------------------------------------------------
pub(crate) fn merge_booking_components(spec: &mut Value) {
    let schemas = [
        (
            "BookingAgentInstructionsBlock",
            booking_instructions_block_schema(),
        ),
        (
            "BookingAvailabilityInput",
            crate::mcp::booking_availability_input_schema(),
        ),
        ("BookingBookInput", crate::mcp::booking_book_input_schema()),
        (
            "BookingRescheduleInput",
            crate::mcp::booking_reschedule_input_schema(),
        ),
        (
            "BookingCancelInput",
            crate::mcp::booking_cancel_input_schema(),
        ),
        (
            "BookingOperationResponse",
            booking_operation_response_schema(),
        ),
    ];
    let Some(components) = spec.get_mut("components").and_then(Value::as_object_mut) else {
        return;
    };
    let target = components
        .entry("schemas")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .expect("OpenAPI schemas must be an object");
    for (name, schema) in schemas {
        target.insert(name.to_owned(), schema);
    }

    for (operation, request_schema) in [
        (
            oneiron::booking::agent_api::BookingAgentOperation::Availability,
            "BookingAvailabilityInput",
        ),
        (
            oneiron::booking::agent_api::BookingAgentOperation::Book,
            "BookingBookInput",
        ),
        (
            oneiron::booking::agent_api::BookingAgentOperation::Reschedule,
            "BookingRescheduleInput",
        ),
        (
            oneiron::booking::agent_api::BookingAgentOperation::Cancel,
            "BookingCancelInput",
        ),
    ] {
        let path = format!(
            "{}/{{page_token}}/{}",
            super::BOOKING_ROUTE_PREFIX,
            operation.as_str()
        );
        bind_schema_ref(
            spec,
            &path,
            "post",
            "requestBody",
            "application/json",
            request_schema,
        );
        bind_schema_ref(
            spec,
            &path,
            "post",
            "200",
            "application/json",
            "BookingOperationResponse",
        );
    }
    bind_schema_ref(
        spec,
        &format!(
            "{}/{{page_token}}/agent-instructions",
            super::BOOKING_ROUTE_PREFIX
        ),
        "get",
        "200",
        oneiron::booking::agent_api::BOOKING_AGENT_INSTRUCTIONS_MIME,
        "BookingAgentInstructionsBlock",
    );
}

// -------------------------------------------------------------------------
// ONE-207 [RET-207] retrieval depth
//
// `depth` is the engine's `oneiron::Effort`, which lives in a crate with no
// OpenAPI derive. Publishing it HERE, from the engine values themselves,
// keeps one vocabulary on the wire: the document, the reason request body and
// both raw-search query parameters all describe the same closed set, and
// there is no second server-side depth type for them to disagree about.
// -------------------------------------------------------------------------
/// The wire form of every effort the engine defines, in tier order.
pub(crate) fn retrieval_effort_values() -> Vec<&'static str> {
    super::RETRIEVAL_EFFORT_VALUES
        .iter()
        .map(|effort| effort.as_str())
        .collect()
}

fn retrieval_effort_schema() -> Value {
    json!({
        "type": "string",
        "description": "Retrieval effort tier. `minimal` is one direct channel with no graph expansion, reranker, or host backend; `standard` adds one-hop graph expansion and deterministic subqueries and is still model-free; `deep` requires a host-injected backend under a budget lease.",
        "enum": retrieval_effort_values(),
    })
}

pub(crate) fn merge_retrieval_depth_components(spec: &mut Value) {
    let values = retrieval_effort_values();
    if let Some(components) = spec.get_mut("components").and_then(Value::as_object_mut) {
        components
            .entry("schemas")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .expect("OpenAPI schemas must be an object")
            .insert("RetrievalEffort".to_owned(), retrieval_effort_schema());
    }

    constrain_property_to_efforts(spec, "MemoryReasonRequest", "depth", &values);
    for path in ["/api/search/vector", "/api/search/text"] {
        constrain_parameter_to_efforts(spec, path, "get", "depth", &values);
    }
}

/// Stamps the closed effort set onto a generated `string` property, leaving
/// its description, default and example exactly as the derive produced them.
fn constrain_property_to_efforts(
    spec: &mut Value,
    schema_name: &str,
    property: &str,
    values: &[&'static str],
) {
    let Some(target) = spec
        .get_mut("components")
        .and_then(|components| components.get_mut("schemas"))
        .and_then(|schemas| schemas.get_mut(schema_name))
        .and_then(|schema| schema.get_mut("properties"))
        .and_then(|properties| properties.get_mut(property))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    target.insert("enum".to_owned(), json!(values));
}

fn constrain_parameter_to_efforts(
    spec: &mut Value,
    path: &str,
    method: &str,
    parameter: &str,
    values: &[&'static str],
) {
    let Some(parameters) = spec
        .get_mut("paths")
        .and_then(|paths| paths.get_mut(path))
        .and_then(|item| item.get_mut(method))
        .and_then(|operation| operation.get_mut("parameters"))
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    for entry in parameters {
        if entry.get("name").and_then(Value::as_str) != Some(parameter) {
            continue;
        }
        if let Some(schema) = entry.get_mut("schema").and_then(Value::as_object_mut) {
            schema.insert("enum".to_owned(), json!(values));
        }
    }
}
