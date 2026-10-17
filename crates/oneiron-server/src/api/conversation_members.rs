//! Room membership routes. The authenticated actor, not presence, authors the ledger.
use super::{
    core_engine_error, json_payload, parse_entity_id_param, query_params, unix_seconds_now,
};
use crate::{
    auth::{CoreAuth, CoreScope},
    error::{ApiError, EnvelopedApiError},
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
/// A refused room join, in the core error envelope.
fn join_error(error: oneiron::memory::MemoryError) -> ApiError {
    use oneiron::memory::{
        MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE,
        MEMORY_CODE_NOT_FOUND, MEMORY_CODE_OWNER_BINDING_REQUIRED,
    };
    match error.code.as_str() {
        MEMORY_CODE_BAD_REQUEST => ApiError::bad_request(error.message, Some("join")),
        MEMORY_CODE_NOT_FOUND => ApiError::not_found("room", None),
        MEMORY_CODE_FORBIDDEN | MEMORY_CODE_OWNER_BINDING_REQUIRED => {
            ApiError::forbidden_scope("room_join")
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
    let members = server
        .vault
        .membership_at(room, req.at.unwrap_or(u64::MAX))
        .map_err(|e| core_engine_error("members read failed", e))?;
    Ok(Json(json!({"member_ids":members})))
}
