//! CONV-09 reaction routes (OF-372, ONE-1991).
//!
//! Native conversation routes (the missing CONV-01 listing door, minimal
//! shape): toggle, grouped pills listing with `with=reactions`, agent inbox,
//! and the context-pack reaction-signals slot.

use super::core_engine_error;
use super::json_payload;
use super::parse_entity_id_param;
use super::query_params;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
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
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use utoipa::IntoParams;
use utoipa::ToSchema;

/// Mirrored provenance for a reaction toggle.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[schema(example = json!({"connector": "slack", "id": "slack:Ev024BE7LH"}))]
pub(crate) struct ReactionExternalIdPayload {
    /// Connector key the mirrored row came from.
    #[schema(example = "slack")]
    connector: String,
    /// Provider-native event/message correlation id, preserved verbatim.
    #[schema(example = "slack:Ev024BE7LH")]
    id: String,
}

impl ReactionExternalIdPayload {
    fn into_engine(self) -> oneiron::conversation::reaction::ReactionExternalId {
        oneiron::conversation::reaction::ReactionExternalId {
            connector: self.connector,
            id: self.id,
        }
    }
}

/// Toggle request for one reaction.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({"glyph": "👀"}))]
pub(crate) struct ReactionToggleRequest {
    /// Glyph: non-empty, at most 64 Unicode scalar values.
    #[schema(example = "👀")]
    glyph: String,
    /// Reactor PERSON ref; defaults to the auth principal.
    #[serde(default)]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    by: Option<String>,
    /// Occurrence timestamp in Unix seconds; defaults to server time.
    #[serde(default)]
    #[schema(example = 1782357600_u64)]
    at: Option<u64>,
    /// Mirrored provenance; absent ⇒ first-party.
    #[serde(default)]
    #[schema(example = json!({"connector": "slack", "id": "slack:Ev024BE7LH"}))]
    ext: Option<ReactionExternalIdPayload>,
}

/// Toggle response for one reaction.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ReactionToggleResponse {
    /// `put` for a fresh record, `revoked` for a tombstone toggle.
    #[schema(example = "put")]
    state: String,
    /// 32-hex id of the affected reaction record.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    reaction_id: String,
}

/// Toggle one reaction on a conversation message.
///
/// `security` is declared inline like the surface-event route: the shared
/// protected-route list is a contested cross-lane file this ticket does not
/// claim, and utoipa emits the identical block from here.
#[utoipa::path(
    post,
    path = "/v1/core/conversations/{conversation_id}/records/{message_id}/reactions",
    security(("CoreBearer" = [])),
    params(
        ("conversation_id" = String, Path, description = "Hex conversation id."),
        ("message_id" = String, Path, description = "Hex message id inside the conversation.")
    ),
    request_body(content = ReactionToggleRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Reaction toggled.", body = ReactionToggleResponse, content_type = "application/json"),
        (status = 400, description = "Malformed reaction request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:write.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Conversation or message was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Reaction toggle failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn toggle_conversation_message_reaction(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((conversation_id, message_id)): Path<(String, String)>,
    payload: Result<Json<ReactionToggleRequest>, JsonRejection>,
) -> Result<Json<ReactionToggleResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let req = json_payload(payload)?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    let message = parse_entity_id_param(&message_id, "message_id")?;
    super::require_entity_type(
        &server,
        &conversation,
        oneiron::registry::ENTITY_TYPE_CONVERSATION,
        "conversation",
    )?;
    super::require_entity_type(
        &server,
        &message,
        oneiron::registry::ENTITY_TYPE_MESSAGE,
        "message",
    )?;
    require_message_in_conversation(&server, &message, &conversation)?;
    let memory = memory_for_reaction_auth(&server, &auth)?;
    let at = req.at.unwrap_or_else(super::unix_seconds_now);
    let receipt = memory
        .react_to_message(oneiron::memory::ReactToMessageInput {
            message_ref: message.to_hex(),
            by_ref: req.by,
            glyph: req.glyph,
            at,
            ext: req.ext.map(ReactionExternalIdPayload::into_engine),
        })
        .map_err(|error| {
            tracing::error!(error = %error, "reaction toggle failed");
            memory_reaction_error(error)
        })?;
    Ok(Json(ReactionToggleResponse {
        state: receipt.state,
        reaction_id: receipt.reaction_id,
    }))
}

fn require_message_in_conversation(
    server: &SyncServer,
    message: &oneiron::EntityId,
    conversation: &oneiron::EntityId,
) -> Result<(), EnvelopedApiError> {
    let targets = server
        .vault
        .targets(message, oneiron::EdgeKind::BelongsTo, None)
        .map_err(|error| {
            tracing::error!(error = %error, "reaction conversation check failed");
            core_engine_error("reaction conversation check failed", error)
        })?;
    if targets.iter().any(|target| target == conversation) {
        return Ok(());
    }
    Err(crate::error::ApiError::not_found("message", Some(&message.to_hex())).into())
}

fn memory_for_reaction_auth<'a>(
    server: &'a Arc<SyncServer>,
    auth: &CoreAuth,
) -> Result<oneiron::Memory<'a>, EnvelopedApiError> {
    let (actor, class) = reaction_actor(auth)?;
    Ok(server.vault.memory(actor, class))
}

/// Write identity for reaction routes, from the credential and nowhere else.
///
/// Same contract as the facade projection: `principal_ref` + `actor_class`
/// are both required, and their absence is a `403` the handler raises rather
/// than a `401` the extractor raises. The engine re-checks per write that the
/// named principal exists and admits the asserted class.
fn reaction_actor(
    auth: &CoreAuth,
) -> Result<(oneiron::EntityId, oneiron::EdgeActorClass), EnvelopedApiError> {
    let principal_ref = auth.principal_ref().ok_or_else(|| {
        crate::error::ApiError::forbidden_scope(
            "reaction routes bind to an authenticated principal",
        )
    })?;
    let actor = parse_entity_id_param(principal_ref, "principal_ref")?;
    let class = match auth.actor_class() {
        Some("human") => oneiron::EdgeActorClass::Human,
        Some("agent") => oneiron::EdgeActorClass::Agent,
        Some("system") => oneiron::EdgeActorClass::System,
        None | Some(_) => {
            return Err(crate::error::ApiError::forbidden_scope(
                "reaction routes bind to a declared actor class",
            )
            .into());
        }
    };
    Ok((actor, class))
}

fn memory_reaction_error(error: oneiron::MemoryError) -> EnvelopedApiError {
    match error.code.as_str() {
        "NOT_FOUND" => crate::error::ApiError::not_found("entity", None).into(),
        "FORBIDDEN" => crate::error::ApiError::forbidden_scope("reaction").into(),
        "INVALID_STATE" => crate::error::ApiError::invalid_state(None).into(),
        _ => crate::error::ApiError::bad_request(error.message, None).into(),
    }
}

/// Listing query for conversation messages with optional reaction pills.
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ConversationMessagesQuery {
    /// Maximum number of messages to return.
    #[serde(default = "super::default_limit")]
    #[schema(default = "super::default_limit", example = 10)]
    #[param(default = 10, example = 10)]
    pub(crate) limit: usize,
    /// Optional exclusive cursor message id.
    #[serde(default)]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    #[param(example = "0123456789abcdef0123456789abcdef")]
    pub(crate) after: Option<String>,
    /// Projection view. Defaults to summary.
    #[serde(default)]
    #[schema(example = "summary")]
    #[param(example = "summary")]
    pub(crate) view: Option<View>,
    /// Count precision for response metadata. Defaults to exact.
    #[serde(default, rename = "countMode", alias = "count_mode")]
    #[schema(example = "exact")]
    #[param(example = "exact")]
    pub(crate) count_mode: CountMode,
    /// `reactions` includes grouped pills in one batched read.
    #[serde(default)]
    #[schema(example = "reactions")]
    #[param(example = "reactions")]
    pub(crate) with: Option<String>,
}

/// One conversation message with optional grouped reaction pills.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ConversationMessageWithReactions {
    /// Hex message id.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: String,
    /// Projected message entity.
    item: Value,
    /// Grouped reaction pills (`with=reactions` only).
    #[serde(skip_serializing_if = "Option::is_none")]
    reactions: Option<Vec<CoreReactionPill>>,
    /// Room outbound posture for reactions.
    #[serde(skip_serializing_if = "Option::is_none", rename = "reactions_outbound")]
    reactions_outbound: Option<String>,
}

/// One grouped reaction pill.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreReactionPill {
    /// Glyph.
    #[schema(example = "👀")]
    glyph: String,
    /// Live count (revoked never counts).
    #[schema(example = 2)]
    count: usize,
    /// Reactors in first-put order.
    by: Vec<String>,
    /// Whether the caller reacted with this glyph.
    #[schema(example = false)]
    mine: bool,
}

/// List conversation messages, with `with=reactions` for grouped pills.
///
/// Messages are the MESSAGE children of the conversation's turns (turn
/// `ChildOf` conversation, message `BelongsTo` conversation), paged in turn
/// order. `with=reactions` attaches one batched pills read across the page
/// (zero per-record calls) plus the room's `reactions_outbound` posture.
#[utoipa::path(
    get,
    path = "/v1/core/conversations/{conversation_id}/records",
    security(("CoreBearer" = [])),
    params(
        ("conversation_id" = String, Path, description = "Hex conversation id."),
        ConversationMessagesQuery
    ),
    responses(
        (status = 200, description = "Conversation messages.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed conversation id or query.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Conversation was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Message listing failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn list_conversation_messages(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(conversation_id): Path<String>,
    query: Result<Query<ConversationMessagesQuery>, QueryRejection>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    super::require_entity_type(
        &server,
        &conversation,
        oneiron::registry::ENTITY_TYPE_CONVERSATION,
        "conversation",
    )?;
    let params = query_params(query)?;
    let view = params.view.unwrap_or(View::Summary);
    let limit = super::core_list_limit(params.limit);
    let after = params
        .after
        .as_deref()
        .map(|after| parse_entity_id_param(after, "after"))
        .transpose()?;
    let with_reactions = params.with.as_deref() == Some("reactions");
    let (viewer, _) = reaction_actor(&auth)?;
    let limit = limit.min(oneiron::conversation::reaction::GROUPED_PILLS_MAX_MESSAGES);
    let message_ids = server
        .vault
        .visible_conversation_messages(&conversation, &viewer, after, limit)
        .map_err(|error| core_engine_error("conversation message listing failed", error))?;
    let items = super::project_entity_ids(&server.vault, message_ids.clone(), view)?;
    let groups = if with_reactions {
        let memory = memory_for_reaction_auth(&server, &auth)?;
        let pills = server
            .vault
            .grouped_reaction_pills(&message_ids, &viewer)
            .map_err(|error| core_engine_error("reaction pills failed", error))?;
        let outbound = memory
            .reactions_outbound(&conversation.to_hex())
            .map_err(|error| {
                tracing::error!(error = %error, "reactions outbound failed");
                memory_reaction_error(error)
            })?;
        Some((pills, outbound.as_str().to_owned()))
    } else {
        None
    };
    let rows: Vec<ConversationMessageWithReactions> = message_ids
        .iter()
        .zip(items)
        .enumerate()
        .map(|(index, (id, item))| {
            let (reactions, reactions_outbound) = match &groups {
                Some((pills, outbound)) => {
                    let group = &pills[index];
                    let core_pills = group
                        .pills
                        .iter()
                        .map(|pill| CoreReactionPill {
                            glyph: pill.glyph.clone(),
                            count: pill.count,
                            by: pill.by.clone(),
                            mine: pill.mine,
                        })
                        .collect();
                    (Some(core_pills), Some(outbound.clone()))
                }
                None => (None, None),
            };
            ConversationMessageWithReactions {
                id: id.to_hex(),
                item,
                reactions,
                reactions_outbound,
            }
        })
        .collect();
    let row_count = rows.len() as u64;
    let response = PaginatedResponse::new(
        rows,
        message_ids.last().map(oneiron::EntityId::to_hex),
        match params.count_mode {
            CountMode::None => ResponseMeta::none(),
            CountMode::Estimate => ResponseMeta::estimate(row_count),
            CountMode::Exact => ResponseMeta::new(row_count, CountMode::Exact),
        },
    );
    Ok(Json(serde_json::to_value(response).map_err(|_| {
        crate::error::ApiError::internal_server_error("reaction listing failed")
    })?))
}

/// Agent inbox query: reactions on a person's messages since `since`.
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct PersonReactionsQuery {
    /// Occurrence floor in Unix seconds.
    #[serde(default)]
    #[schema(example = 1782357600_u64)]
    #[param(example = 1782357600_u64)]
    pub(crate) since: u64,
}

/// One agent reaction signal.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreReactionSignal {
    /// `reaction.put` or `reaction.revoked`.
    #[schema(example = "reaction.put")]
    pub(crate) kind: String,
    /// 32-hex reaction record id.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    pub(crate) reaction: String,
    /// 32-hex message id.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    pub(crate) message: String,
    /// 32-hex reactor person id.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    pub(crate) by: String,
    /// Glyph.
    #[schema(example = "👀")]
    pub(crate) glyph: String,
    /// Occurrence timestamp.
    #[schema(example = 1782357600_u64)]
    pub(crate) at: u64,
    /// Record timestamp.
    #[schema(example = 1782357635_u64)]
    pub(crate) recorded_at: u64,
}

/// List reaction signals for one person since `since`.
///
/// The record IS the event: live rows report `reaction.put`, tombstoned rows
/// report `reaction.revoked` (revoked never counts in pills but always
/// signals here). Surfaced in context-pack responses as the "signals since
/// your last turn" slot; this route is the direct read.
#[utoipa::path(
    get,
    path = "/v1/core/persons/{person_id}/reactions",
    security(("CoreBearer" = [])),
    params(
        ("person_id" = String, Path, description = "Hex person id."),
        PersonReactionsQuery
    ),
    responses(
        (status = 200, description = "Reaction signals.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed person id or query.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Person was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Reaction inbox read failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn list_person_reactions(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(person_id): Path<String>,
    query: Result<Query<PersonReactionsQuery>, QueryRejection>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let person = parse_entity_id_param(&person_id, "person_id")?;
    super::require_entity_type(
        &server,
        &person,
        oneiron::registry::ENTITY_TYPE_PERSON,
        "person",
    )?;
    let params = query_params(query)?;
    let memory = memory_for_reaction_auth(&server, &auth)?;
    let signals = memory
        .reactions_since(Some(person.to_hex()), params.since)
        .map_err(|error| {
            tracing::error!(error = %error, "reaction inbox failed");
            memory_reaction_error(error)
        })?;
    let rows: Vec<CoreReactionSignal> = signals
        .into_iter()
        .map(|signal| CoreReactionSignal {
            kind: signal.kind.as_str().to_owned(),
            reaction: signal.reaction,
            message: signal.message,
            by: signal.by,
            glyph: signal.glyph,
            at: signal.at,
            recorded_at: signal.recorded_at,
        })
        .collect();
    let response = PaginatedResponse::new(rows, None, ResponseMeta::none());
    Ok(Json(serde_json::to_value(response).map_err(|_| {
        crate::error::ApiError::internal_server_error("reaction inbox failed")
    })?))
}

/// Reaction signals for a context-pack request.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct ContextPackReactionSignals {
    /// Person whose messages carry the signals.
    #[serde(default)]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    pub(crate) person: Option<String>,
    /// Occurrence floor in Unix seconds.
    #[serde(default)]
    #[schema(example = 1782357600_u64)]
    pub(crate) since: Option<u64>,
}
