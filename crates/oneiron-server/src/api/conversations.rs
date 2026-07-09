use super::CORE_MAX_LIST_LIMIT;
use super::CoreCreateEntityRequest;
use super::CoreEntityWriteInput;
use super::CoreEntityWriteResponse;
use super::CoreListQuery;
use super::CoreTextField;
use super::SearchResponse;
use super::ViewQuery;
use super::collect_live_entity_page;
use super::core_body_for_write;
use super::core_engine_error;
use super::core_entity_timestamps;
use super::core_list_entities_by_type;
use super::core_list_limit;
use super::encode_core_body;
use super::is_deleted_shell_for_core_list;
use super::json_payload;
use super::parse_entity_id_param;
use super::parse_optional_entity_id;
use super::project_core_entity;
use super::project_entity_ids;
use super::query_params;
use super::require_entity_type;
use super::stage_core_entity_put;
use super::write_core_entity;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::projection;
use crate::projection::View;
use crate::protocol::CountMode;
use crate::protocol::PaginatedResponse;
use crate::protocol::ResponseMeta;
use crate::server::SyncServer;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::extract::rejection::QueryRejection;
use axum::response::Json;
use oneiron::EdgeKind;
use oneiron::registry::ENTITY_TYPE_CONVERSATION;
use oneiron::registry::ENTITY_TYPE_TURN;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use utoipa::ToSchema;

/// Core turn create request.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "body": { "txt": "I saw a blue hallway door.", "spkr": "user", "at": 1782357600_u64 },
    "text": [{ "field": "body", "value": "I saw a blue hallway door." }]
}))]
pub(crate) struct CoreCreateTurnRequest {
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
pub(crate) async fn list_core_conversations(
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
pub(crate) async fn create_core_conversation(
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
pub(crate) async fn list_core_conversation_turns(
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
pub(crate) async fn create_core_conversation_turn(
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

    let body = core_body_for_write(ENTITY_TYPE_TURN, &req.body);
    let item = projection::project_entity_parts(
        &id,
        ENTITY_TYPE_TURN,
        timestamps.learned_at,
        &encode_core_body(&body)?,
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
pub(crate) async fn get_core_turn(
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

pub(crate) fn core_list_conversation_turns(
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

pub(crate) fn count_live_conversation_turns(
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
