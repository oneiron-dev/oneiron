//! Conversation record and thread routes. `as` is a listing filter, not an authorization boundary.
use super::{
    conversation_members::actor, core_engine_error, json_payload, parse_entity_id_param,
    query_params, unix_seconds_now,
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
    EntityId, TimeRange, WriteEnvelope, WriteProvenance,
    conversation::{AppendRecord, ScopeSelector},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
#[derive(Default, Deserialize)]
pub(super) struct RecordQuery {
    #[serde(rename = "as")]
    person: Option<EntityId>,
    #[serde(rename = "with")]
    include: Option<String>,
    #[serde(default)]
    after: Option<EntityId>,
    #[serde(default)]
    limit: Option<usize>,
}
#[derive(Deserialize)]
pub(super) struct RecordWrite {
    #[serde(default)]
    id: Option<EntityId>,
    #[serde(default)]
    actor: Option<EntityId>,
    #[serde(default)]
    parent: Option<EntityId>,
    #[serde(default)]
    at: Option<u64>,
    body: Value,
}
#[derive(Deserialize)]
pub(super) struct SummaryWrite {
    text: String,
    #[serde(default)]
    actor: Option<EntityId>,
}
fn checked_trunk(
    server: &SyncServer,
    room: EntityId,
    trunk: EntityId,
) -> Result<(), EnvelopedApiError> {
    if !server
        .vault
        .targets(&trunk, oneiron::EdgeKind::ChildOf, None)
        .map_err(|e| core_engine_error("record room failed", e))?
        .contains(&room)
    {
        return Err(ApiError::not_found("conversation record", Some(&trunk.to_hex())).into());
    }
    Ok(())
}
pub(super) async fn records(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(room): Path<String>,
    query: Result<Query<RecordQuery>, QueryRejection>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let room = parse_entity_id_param(&room, "conversation_id")?;
    let req = query_params(query)?;
    let limit = req.limit.unwrap_or(100).min(1000);
    let mut after = req.after;
    let mut items = Vec::new();
    if limit == 0 {
        return Ok(Json(json!({"items":[],"next_cursor":null})));
    }
    loop {
        let page = server
            .vault
            .sources_page(&room, oneiron::EdgeKind::ChildOf, None, after.as_ref(), 256)
            .map_err(|e| core_engine_error("record list failed", e))?;
        if page.is_empty() {
            after = None;
            break;
        }
        for id in &page {
            after = Some(*id);
            if let Some(person) = req.person
                && !server
                    .vault
                    .record_visible_to(*id, person)
                    .map_err(|e| core_engine_error("record visibility failed", e))?
            {
                continue;
            }
            let mut item =
                super::project_core_entity(&server.vault, id, crate::projection::View::Full)?.0;
            if req.include.as_deref() == Some("thread_meta") {
                item["thread_meta"] = json!(
                    server
                        .vault
                        .thread_meta(*id)
                        .map_err(|e| core_engine_error("thread metadata failed", e))?
                );
            }
            items.push(item);
            if items.len() >= limit {
                break;
            }
        }
        if items.len() >= limit {
            break;
        }
        if page.len() < 256 {
            after = None;
            break;
        }
    }
    Ok(Json(json!({"items":items,"next_cursor":after})))
}
pub(super) async fn append(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(room): Path<String>,
    payload: Result<Json<RecordWrite>, JsonRejection>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let room = parse_entity_id_param(&room, "conversation_id")?;
    let req = json_payload(payload)?;
    let at = req.at.unwrap_or_else(unix_seconds_now);
    let input = AppendRecord {
        conversation: room,
        id: req.id.unwrap_or_else(EntityId::now),
        parent: req.parent,
        advance: true,
        body: req.body,
        occurred: TimeRange { start: at, end: at },
        learned_at: at,
        actor: actor(&auth, req.actor)?,
    };
    let id = server
        .vault
        .append_record(&input)
        .map_err(|e| core_engine_error("append record failed", e))?;
    Ok(Json(json!({"id":id})))
}
pub(super) async fn thread(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((room, trunk)): Path<(String, String)>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let room = parse_entity_id_param(&room, "conversation_id")?;
    let trunk = parse_entity_id_param(&trunk, "record_id")?;
    checked_trunk(&server, room, trunk)?;
    Ok(Json(json!(server.vault.thread(trunk).map_err(|e| {
        core_engine_error("thread read failed", e)
    })?)))
}
pub(super) async fn reply(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((room, trunk)): Path<(String, String)>,
    payload: Result<Json<RecordWrite>, JsonRejection>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let room = parse_entity_id_param(&room, "conversation_id")?;
    let trunk = parse_entity_id_param(&trunk, "record_id")?;
    checked_trunk(&server, room, trunk)?;
    let req = json_payload(payload)?;
    let at = req.at.unwrap_or_else(unix_seconds_now);
    let input = AppendRecord {
        conversation: room,
        id: req.id.unwrap_or_else(EntityId::now),
        parent: None,
        advance: false,
        body: req.body,
        occurred: TimeRange { start: at, end: at },
        learned_at: at,
        actor: actor(&auth, req.actor)?,
    };
    let id = server
        .vault
        .reply_in_thread(trunk, &input)
        .map_err(|e| core_engine_error("thread reply failed", e))?;
    Ok(Json(
        json!({"id":id,"thread":server.vault.thread(trunk).map_err(|e|core_engine_error("thread read failed",e))?}),
    ))
}
pub(super) async fn summary(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((room, trunk)): Path<(String, String)>,
    payload: Result<Json<SummaryWrite>, JsonRejection>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let room = parse_entity_id_param(&room, "conversation_id")?;
    let trunk = parse_entity_id_param(&trunk, "record_id")?;
    checked_trunk(&server, room, trunk)?;
    let req = json_payload(payload)?;
    let actor = actor(&auth, req.actor)?;
    let provenance = WriteProvenance::new(rmpv::Value::from("conversation_summary"))
        .map_err(|e| core_engine_error("summary provenance failed", e))?;
    let envelope = WriteEnvelope::new(
        actor,
        oneiron::ClaimSource::UserStated,
        provenance,
        oneiron::ClaimApprovalStatus::Proposed,
    );
    let id = server
        .vault
        .summarize_thread(trunk, &req.text, &envelope, unix_seconds_now())
        .map_err(|e| core_engine_error("thread summary failed", e))?;
    Ok(Json(json!({"id":id})))
}
pub(super) async fn canonical(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(room): Path<String>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let room = parse_entity_id_param(&room, "conversation_id")?;
    Ok(Json(
        json!({"records":server.vault.resolve_scope(&ScopeSelector::Canonical(room),false).map_err(|e|core_engine_error("canonical read failed",e))?}),
    ))
}
