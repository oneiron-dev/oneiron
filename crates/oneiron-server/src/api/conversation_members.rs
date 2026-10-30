//! Room membership routes. The authenticated actor, not presence, authors the ledger.
use super::{
    core_engine_error, json_payload, parse_entity_id_param, query_params, unix_seconds_now,
};
use crate::{
    auth::{CoreAuth, CoreScope},
    error::{ApiError, ApiErrorDetails, ApiErrorEnvelope, EnvelopedApiError},
    server::SyncServer,
};
use axum::{
    Json,
    extract::{
        Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
};
use oneiron::{
    EdgeActorClass, EntityId, WriteActor,
    conversation::{HistoryChoice, MembershipAction},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

pub(super) fn actor(auth: &CoreAuth, requested: Option<EntityId>) -> Result<WriteActor, ApiError> {
    let bound = auth
        .principal_ref()
        .map(|s| parse_entity_id_param(s, "principal_ref"))
        .transpose()?;
    let id = match (bound, requested) {
        (Some(bound), None) => bound,
        (Some(bound), Some(id)) if bound == id => id,
        (_, Some(id)) => {
            auth.require(CoreScope::Auth)?;
            id
        }
        _ => {
            return Err(ApiError::bad_request(
                "actor is required unless auth binds principal_ref",
                Some("actor"),
            ));
        }
    };
    let class = match auth
        .actor_class()
        .or_else(|| auth.is_owner_grade().then_some("human"))
    {
        Some("human") => EdgeActorClass::Human,
        Some("agent") => EdgeActorClass::Agent,
        _ => return Err(ApiError::forbidden_scope("human_or_agent")),
    };
    Ok(WriteActor::new(id, class))
}
#[derive(Deserialize)]
pub(super) struct MemberWrite {
    person_id: EntityId,
    action: MembershipAction,
    #[serde(default)]
    actor: Option<EntityId>,
    #[serde(default)]
    at: Option<u64>,
    #[serde(default)]
    history: HistoryChoice,
    #[serde(default)]
    from: Option<u64>,
    /// Join's idempotency key: the same key replays the join.
    #[serde(default)]
    intent_key: Option<String>,
}
#[derive(Default, Deserialize)]
pub(super) struct MemberQuery {
    at: Option<u64>,
}
/// Join, leave or set history visibility for one room member.
#[utoipa::path(
    post,
    path = "/v1/core/conversations/{conversation_id}/members",
    params(("conversation_id" = String, Path, description = "Hex conversation id.")),
    request_body(content = Object, description = "`MemberWrite`: `person_id` (32 hex), `action` (`join`, `leave` or `history`), an optional `actor` (32 hex), `at`, `history` (`inherit`, `share` or `none`), `from`, and a join's `intent_key`.", content_type = "application/json"),
    responses(
        (status = 200, description = "The room's member ids, and a join's decision.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed conversation id or request body, or a join without its key.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:write, or the join is refused.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Room was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 409, description = "The key's first request never settled an outcome (`idempotent_outcome_unknown`, FIX 9527): its effect may have landed, so it is not run again; read the resource's state, or send a new `Idempotency-Key` to act again. A retry whose first request counted committed writes gets `idempotent_reply_not_kept` instead (FIX 10379): those writes landed, and the reply was not kept.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Membership update failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(super) async fn write_member(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(room): Path<String>,
    payload: Result<Json<MemberWrite>, JsonRejection>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let room = parse_entity_id_param(&room, "conversation_id")?;
    let req = json_payload(payload)?;
    let actor = actor(&auth, req.actor)?;
    let at = req.at.unwrap_or_else(unix_seconds_now);
    let result = match req.action {
        // A person takes a room seat only through the room's join door, which
        // proves the caller stands for that person and seats it only once the
        // join is Ready (#2008); a Hold or a refusal is returned as decided.
        // A first entry into an ordinary room records its P5 entry fact with
        // the seat and sees the history asked for (OF-365); any other join
        // keeps the room's own rule.
        MembershipAction::Join => {
            if req.at.is_some() {
                return Err(
                    ApiError::bad_request("Join uses the current time", Some("join")).into(),
                );
            }
            let intent_key = req.intent_key.ok_or_else(|| {
                ApiError::bad_request("intent_key is required for Join", Some("intent_key"))
            })?;
            let join = server
                .vault
                .memory(actor.entity_ref(), actor.actor_class())
                .rooms_join_entering(
                    &oneiron::workspace_roster::JoinRequest {
                        room,
                        branch: None,
                        subject: oneiron::workspace_roster::JoinSubject::Person(req.person_id),
                        paid: false,
                        spend_scope: None,
                        intent_key,
                    },
                    req.history,
                )
                .map_err(join_error)?;
            let members = server
                .vault
                .members(room)
                .map_err(|e| core_engine_error("members read failed", e))?;
            return Ok(Json(json!({"join": join, "member_ids": members})));
        }
        MembershipAction::Leave => server.vault.leave_member(room, req.person_id, actor, at),
        MembershipAction::History => server.vault.set_history_visibility(
            room,
            req.person_id,
            actor,
            at,
            req.from.ok_or_else(|| {
                ApiError::bad_request("from is required for history", Some("from"))
            })?,
        ),
    };
    result.map_err(|e| core_engine_error("membership update failed", e))?;
    let members = server
        .vault
        .members(room)
        .map_err(|e| core_engine_error("members read failed", e))?;
    Ok(Json(json!({"member_ids":members})))
}
/// A refused room join, in the core error envelope. A refusal keeps the
/// engine's code, words and suggestions, bound to `room_join` (FIX 6032).
fn join_error(error: oneiron::memory::MemoryError) -> ApiError {
    use oneiron::memory::{
        MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE,
        MEMORY_CODE_NOT_FOUND, MEMORY_CODE_OWNER_BINDING_REQUIRED,
    };
    match error.code.as_str() {
        MEMORY_CODE_BAD_REQUEST => ApiError::bad_request(error.message, Some("join")),
        MEMORY_CODE_NOT_FOUND => ApiError::not_found("room", None),
        MEMORY_CODE_FORBIDDEN => ApiError::new(
            error.message,
            ApiErrorDetails::Forbidden {
                required_scope: Some("room_join".to_owned()),
            },
            error.suggestions,
        ),
        MEMORY_CODE_OWNER_BINDING_REQUIRED => {
            ApiError::owner_binding_required(error.message, Some("room_join"), error.suggestions)
        }
        MEMORY_CODE_INVALID_STATE => ApiError::invalid_state(Some("room_join")),
        _ => {
            tracing::error!(code = %error.code, "room join failed");
            ApiError::internal_server_error("room join failed")
        }
    }
}

pub(super) async fn read_members(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(room): Path<String>,
    query: Result<Query<MemberQuery>, QueryRejection>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    // The ledger read is unkeyed: a credential narrowed to some records
    // cannot bound it.
    auth.require_unrestricted_record_scope()?;
    let room = parse_entity_id_param(&room, "conversation_id")?;
    let req = query_params(query)?;
    // FIX 8209: the room and its roster are admitted through the caller's
    // own lane at its destination and the room's audience, in one snapshot:
    // the owner, a member, a reader on a grant that opens the room's
    // relationship, and a reader that sat in the room at `at` read it. Any
    // other caller meets the answer a missing room gets.
    let read = super::scoped_read_for_core_auth(&server.vault, &auth)?;
    let members = server
        .vault
        .room_roster_admitted(&read, &room, req.at.unwrap_or(u64::MAX))
        .map_err(|e| core_engine_error("members read failed", e))?
        .ok_or_else(|| core_engine_error("members read failed", oneiron::Error::EntityNotFound))?;
    Ok(Json(json!({"member_ids":members})))
}
