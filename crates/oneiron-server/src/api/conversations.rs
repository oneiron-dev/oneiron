//! The `/v1/core/conversations` and `/v1/core/turns` routes: conversations and their turns.
//! `CoreCreateTurnRequest` and the `*_core_conversation*` handlers are its call surface.
//! `crate::api::conversations` defines these DTOs; the engine owns the turn rows.
mod turn_reads;

use self::turn_reads::{core_list_conversation_turns, core_turn_for_read};
use super::CoreCreateEntityRequest;
use super::CoreEntityWriteResponse;
use super::CoreListQuery;
use super::CoreTextField;
use super::DagTurnQuery;
use super::DagWriteError;
use super::SearchResponse;
use super::core_engine_error;
use super::core_entity_timestamps;
use super::core_list_limit;
use super::core_private_threads_admit;
use super::core_write_text;
use super::encode_core_body;
use super::facade::ROOM_TURN_HEADER;
use super::json_payload;
use super::parse_entity_id_param;
use super::project_core_entity;
use super::query_params;
use super::require_entity_type;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorDetails;
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
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use oneiron::claim::ScopedReadReceipt;
use oneiron::core_write::{
    ConversationCreateInput, ConversationTurnCreateInput, CoreEntityWriteReceipt,
};
use oneiron::memory::{
    ConversationListFilter, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_OWNER_BINDING_REQUIRED, MemoryError,
};
use oneiron::registry::ENTITY_TYPE_CONVERSATION;
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::task_verb::sdk::AgentVerb;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
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

#[derive(Debug, Deserialize)]
pub(crate) struct ConversationListQuery {
    #[serde(default = "super::default_limit")]
    limit: usize,
    #[serde(default)]
    after: Option<String>,
    #[serde(default)]
    view: Option<View>,
    #[serde(default, rename = "countMode", alias = "count_mode")]
    count_mode: CountMode,
    #[serde(default)]
    kind: Option<oneiron::conversation::ConversationKind>,
    #[serde(default)]
    external_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateConversationRequest {
    #[serde(flatten)]
    entity: CoreCreateEntityRequest,
    #[serde(default)]
    actor: Option<oneiron::EntityId>,
}

/// A list row keeps the existing view projection and adds one optional preview.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ConversationListRow {
    #[serde(flatten)]
    entity: Map<String, Value>,
    #[serde(rename = "lastMessageSnippet", default)]
    last_message_snippet: Option<String>,
}

/// One list page and the receipt of the reads that produced it.
#[derive(Debug, Serialize)]
pub(crate) struct ConversationsListResponse {
    #[serde(flatten)]
    page: PaginatedResponse<ConversationListRow>,
    narrowing: ScopedReadReceipt,
}

/// List the conversations the reader may read, optionally filtered by
/// effective kind and external id.
///
/// The list reads as the credential's principal on the read lane recall and
/// the transcript use (ARCH-0006a, DEC-0005): a conversation the reader may
/// not read is left out, a preview quotes only a message or turn it may read,
/// and the response carries the read's receipt.
#[utoipa::path(
    get,
    path = "/v1/core/conversations",
    params(CoreListQuery),
    responses(
        (status = 200, description = "The conversations the reader may read, each with a preview of the latest message it may read, and the read's `narrowing` receipt.", body = Object, content_type = "application/json"),
        (status = 400, description = "Invalid list query, or a room turn header.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read, or names no principal and actor class.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Conversation listing failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn list_core_conversations(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    query: Result<Query<ConversationListQuery>, QueryRejection>,
) -> Result<Json<ConversationsListResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_lane_record_scope()?;
    // The read is not bounded by a room's ceiling, so a request made inside a
    // room turn is refused rather than read outside it.
    if headers.contains_key(ROOM_TURN_HEADER) {
        return Err(ApiError::bad_request(
            "the conversation list is not served inside a room turn",
            Some(ROOM_TURN_HEADER),
        )
        .into());
    }
    let query = query_params(query)?;
    let after = query
        .after
        .as_deref()
        .map(|after| parse_entity_id_param(after, "after"))
        .transpose()?;
    let (actor, class) = super::conversation_transcript::reader(&auth)?;
    let proof = auth.verified_slip().cloned();
    let locality = auth.locality();
    let view = query.view.unwrap_or(View::Summary);
    let count_mode = query.count_mode;
    let projector = Arc::clone(&server);
    let read = tokio::task::spawn_blocking(move || {
        let memory = server.vault.memory(actor, class).at(locality);
        let memory = match &proof {
            Some(proof) => memory.with_read_proof(proof),
            None => memory,
        };
        let filter = ConversationListFilter {
            kind: query.kind,
            external_id: query.external_id.as_deref(),
        };
        memory.conversation_list(
            filter,
            after.as_ref(),
            core_list_limit(query.limit),
            matches!(count_mode, CountMode::Exact),
        )
    })
    .await
    .unwrap_or_else(|error| {
        tracing::warn!(
            panicked = error.is_panic(),
            "conversation list failed to join"
        );
        Err(MemoryError::new(
            MEMORY_CODE_INTERNAL,
            "the conversation list did not finish",
            &["Retry the call."],
        ))
    })
    .map_err(refusal)?;
    let page = read.value;
    let mut bodies = projection::BodyBudget::new(
        &projector.vault,
        projector.config.limits.projection_body_bytes,
    );
    let items: Vec<_> = page
        .rows
        .into_iter()
        .filter_map(|row| list_row(row, view, &mut bodies))
        .collect();
    let meta = match count_mode {
        CountMode::None => ResponseMeta::none(),
        CountMode::Estimate => ResponseMeta::estimate(items.len() as u64),
        CountMode::Exact => ResponseMeta::new(page.total.unwrap_or_default(), CountMode::Exact),
    };
    Ok(Json(ConversationsListResponse {
        page: PaginatedResponse::new(items, page.next.map(|id| id.to_hex()), meta),
        narrowing: read.receipt,
    }))
}

/// One conversation the lane admitted, in the requested view, with its
/// preview. The full view says when the conversation occurred: an imported
/// one, when its session started.
fn list_row(
    listed: oneiron::memory::ConversationListRow,
    view: View,
    bodies: &mut projection::BodyBudget<'_>,
) -> Option<ConversationListRow> {
    let row = listed.row;
    let Value::Object(mut entity) = bodies.project(
        &row.id,
        row.entity_type,
        row.learned_at,
        row.body.as_deref().unwrap_or_default(),
        view,
    ) else {
        return None;
    };
    if view == View::Full {
        entity.insert(
            "occurred".to_owned(),
            serde_json::json!({ "start": row.occurred.start, "end": row.occurred.end }),
        );
    }
    Some(ConversationListRow {
        entity,
        last_message_snippet: listed.last_message_snippet,
    })
}

/// The engine's refusal in the core error envelope, with the receipt of the
/// read that refused.
fn refusal(error: MemoryError) -> EnvelopedApiError {
    let receipt = error.read_receipt.clone();
    let api = match error.code.as_str() {
        MEMORY_CODE_FORBIDDEN | MEMORY_CODE_OWNER_BINDING_REQUIRED => ApiError::new(
            error.message,
            ApiErrorDetails::Forbidden {
                required_scope: None,
            },
            error.suggestions,
        ),
        _ => {
            tracing::error!(code = %error.code, "conversation list failed");
            ApiError::internal_server_error("conversation listing failed")
        }
    };
    let enveloped = EnvelopedApiError::from(api);
    match receipt {
        Some(receipt) => enveloped.with_read_receipt(*receipt),
        None => enveloped,
    }
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
    headers: HeaderMap,
    extensions: Extensions,
    payload: Result<Json<CreateConversationRequest>, JsonRejection>,
) -> Result<Json<CoreEntityWriteResponse>, DagWriteError> {
    auth.require(CoreScope::Write)?;
    let request = json_payload(payload)?;
    let req = request.entity;
    let body: oneiron::conversation::ConversationBody = serde_json::from_value(req.body.clone())
        .map_err(|_| {
            crate::error::ApiError::bad_request("invalid conversation body", Some("body"))
        })?;
    // The route's own refusals first; the row mints what the body omits.
    if let Some(id) = &req.id {
        parse_entity_id_param(id, "id")?;
    }
    core_entity_timestamps(req.occurred_start, req.occurred_end, req.learned_at)?;
    // A memberful create is authored by the actor the request binds; a
    // plain put names none.
    let members = !body.member_ids.is_empty();
    let actor = members
        .then(|| super::conversation_members::actor(&auth, request.actor))
        .transpose()?;
    let input = ConversationCreateInput {
        id: req.id,
        occurred_start: req.occurred_start,
        occurred_end: req.occurred_end,
        learned_at: req.learned_at,
        body: req.body,
        text: core_write_text(req.text),
    };
    // OF-181: `vault.conversations.create`, as an action when the
    // credential binds one that writes as this actor, else through the
    // row's own Vault door as the actor the request bound, held to the
    // credential's write lane (FIX 10781).
    let receipt =
        match super::facade::action_routes::rest_action_bound(&server, &auth, &headers, &input)? {
            Some(bound) if actor.is_none_or(|actor| actor == bound.writes_as()) => {
                let row = AgentVerb::VaultConversationsCreate;
                let key =
                    super::facade::action_routes::rest_action_key(&server, &auth, &headers, row)?;
                let output = super::facade::action_routes::execute_facade_row(
                    &server, headers, extensions, bound, row, &input, key,
                )
                .await?;
                entity_receipt(output)?
            }
            _ => {
                let lane = super::facade::host_doors::core_write_lane(&server.vault, &auth)?;
                server.vault.write_core_conversation(&input, actor, &lane)?
            }
        };
    let id = parse_entity_id_param(&receipt.id, "id")?;
    let item = if members {
        project_core_entity(&server.vault, &id, View::Full)?.0
    } else {
        projection::project_entity_parts(
            &id,
            ENTITY_TYPE_CONVERSATION,
            receipt.learned_at,
            &encode_core_body(&receipt.body)?,
            View::Full,
        )
    };
    Ok(Json(CoreEntityWriteResponse {
        id: receipt.id,
        entity_type: ENTITY_TYPE_CONVERSATION,
        item,
    }))
}

/// A core write row's action output, as its receipt.
fn entity_receipt(output: Value) -> Result<CoreEntityWriteReceipt, ApiError> {
    serde_json::from_value(output)
        .map_err(|_| ApiError::internal_server_error("write result encoding failed"))
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
    auth.require_unrestricted_record_scope()?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    require_entity_type(
        &server,
        &conversation,
        ENTITY_TYPE_CONVERSATION,
        "conversation",
    )?;
    let params = query_params(query)?;
    let read = super::scoped_auth::scoped_read_for_core_auth(&server.vault, &auth)?;
    core_list_conversation_turns(
        &server.vault,
        &read,
        &conversation,
        params,
        server.config.limits.projection_body_bytes,
    )
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
    headers: HeaderMap,
    extensions: Extensions,
    payload: Result<Json<CoreCreateTurnRequest>, JsonRejection>,
) -> Result<Json<CoreEntityWriteResponse>, DagWriteError> {
    auth.require(CoreScope::Write)?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    require_entity_type(
        &server,
        &conversation,
        ENTITY_TYPE_CONVERSATION,
        "conversation",
    )?;
    let req = json_payload(payload)?;
    // The route's own refusals first; the row mints what the body omits.
    if let Some(id) = &req.id {
        parse_entity_id_param(id, "id")?;
    }
    core_entity_timestamps(req.occurred_start, req.occurred_end, req.learned_at)?;
    let input = ConversationTurnCreateInput {
        conversation: conversation.to_hex(),
        id: req.id,
        occurred_start: req.occurred_start,
        occurred_end: req.occurred_end,
        learned_at: req.learned_at,
        body: req.body,
        text: core_write_text(req.text),
    };
    // OF-181: `vault.conversations.turns.create`, as an action when the
    // credential binds one, else through the row's own door. Either lands
    // the turn on the vault once.
    let receipt =
        match super::facade::action_routes::rest_action_bound(&server, &auth, &headers, &input)? {
            Some(bound) => {
                let row = AgentVerb::VaultConversationsTurnsCreate;
                let key =
                    super::facade::action_routes::rest_action_key(&server, &auth, &headers, row)?;
                let output = super::facade::action_routes::execute_facade_row(
                    &server, headers, extensions, bound, row, &input, key,
                )
                .await?;
                entity_receipt(output)?
            }
            None => super::facade::host_doors::write_core_turn(&server, &auth, input).await?,
        };
    let id = parse_entity_id_param(&receipt.id, "id")?;
    let item = projection::project_entity_parts(
        &id,
        ENTITY_TYPE_TURN,
        receipt.learned_at,
        &encode_core_body(&receipt.body)?,
        View::Full,
    );
    Ok(Json(CoreEntityWriteResponse {
        id: receipt.id,
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
        DagTurnQuery
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
    query: Result<Query<DagTurnQuery>, QueryRejection>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    let id = parse_entity_id_param(&turn_id, "turn_id")?;
    require_entity_type(&server, &id, ENTITY_TYPE_TURN, "turn")?;
    // A turn of a private thread the caller does not read, the opener
    // included, answers as one that is not here, before any view of it
    // (FIX 5652); below the owner, so does one its lane does not read (FIX
    // 5938). Its reply strip holds the turn it answers so too.
    let read = super::scoped_auth::scoped_read_for_core_auth(&server.vault, &auth)?;
    // Its query's refusal comes after the turn's admission and before its
    // words are read (FIX 5870).
    let (params, (entity_type, learned_at, body)) =
        core_turn_for_read(&server.vault, &read, &id, turn_read_query(query))?;
    let view = params.view.unwrap_or(View::Full);
    // The words its admission read, in that same snapshot (FIX 5870).
    let mut item = projection::project_entity_parts(&id, entity_type, learned_at, &body, view);
    if params.with.as_deref() == Some("reply_strip") {
        let strip = server
            .vault
            .reply_strip(&read, &id)
            .map_err(|e| core_engine_error("reply strip read failed", e))?;
        item["reply_strip"] = strip.map_or(Value::Null, |strip| {
            serde_json::json!({
                "record": strip.record.to_hex(), "revision": strip.revision,
                "text": strip.text, "stale": strip.stale, "withheld": strip.withheld,
            })
        });
    }
    Ok(Json(item))
}

/// The single TURN read's query, refused when it names a projection that
/// read does not make.
fn turn_read_query(
    query: Result<Query<DagTurnQuery>, QueryRejection>,
) -> Result<DagTurnQuery, EnvelopedApiError> {
    let params = query_params(query)?;
    if params
        .with
        .as_deref()
        .is_some_and(|with| with != "reply_strip")
    {
        return Err(
            crate::error::ApiError::bad_request("unknown TURN projection", Some("with")).into(),
        );
    }
    Ok(params)
}

/// Whether the TURN routes serve `read`'s caller as the vault owner
/// (`Vault::turn_doors_owner`, FIX 5938).
fn core_turn_doors_owner(
    vault: &oneiron::Vault,
    read: &oneiron::claim::ScopedRead<'_>,
) -> Result<bool, ApiError> {
    vault.turn_doors_owner(read).map_err(|error| {
        tracing::error!(error = %error, "core TURN owner check failed");
        core_engine_error("core TURN owner check failed", error)
    })
}

/// Whether the TURN routes serve the row `id` to `read`'s caller: the
/// owner's own read (`owner`) under each private thread alone, as before
/// (FIX 5652); any other under its lane's whole row admission, private
/// threads included (FIX 5938).
fn core_turn_admits(
    vault: &oneiron::Vault,
    read: &oneiron::claim::ScopedRead<'_>,
    owner: bool,
    id: &oneiron::EntityId,
) -> Result<bool, ApiError> {
    if owner {
        return core_private_threads_admit(vault, read, id);
    }
    read.is_entity_readable(id).map_err(|error| {
        tracing::error!(error = %error, id = %id.to_hex(), "core TURN admission failed");
        core_engine_error("core TURN admission failed", error)
    })
}

/// Whether the TURN routes serve the turn `id` to `read`'s caller at all, as
/// [`get_core_turn`] decides it (FIX 5652, 5938). A route that reads beside a
/// TURN, its VAD annotation or its sub-sessions, answers one this does not
/// serve as missing (FIX 5868, 5869).
pub(crate) fn core_turn_served(
    vault: &oneiron::Vault,
    read: &oneiron::claim::ScopedRead<'_>,
    id: &oneiron::EntityId,
) -> Result<bool, ApiError> {
    let owner = core_turn_doors_owner(vault, read)?;
    core_turn_admits(vault, read, owner, id)
}

#[cfg(test)]
mod tests;
