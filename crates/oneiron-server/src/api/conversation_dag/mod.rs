//! HTTP adapters for transactional conversation DAG and summary doors.

mod types;
use super::{
    CoreEntityWriteResponse, core_body_for_write, core_engine_error, core_entity_timestamps,
    core_text_fields, encode_core_body, json_payload, parse_entity_id_param, project_core_entity,
    query_params,
};
use crate::auth::{CoreAuth, CoreScope};
use crate::error::{ApiErrorEnvelope, EnvelopedApiError};
use crate::projection::View;
use crate::server::SyncServer;
use axum::Json;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use oneiron::EntityId;
use oneiron::conversation_dag::{AppendRecord, DagPageRequest};
use oneiron::registry::ENTITY_TYPE_TURN;
use std::sync::Arc;
use types::parse_optional;
pub(crate) use types::*;

fn ids(records: Vec<EntityId>) -> Vec<String> {
    records.into_iter().map(|id| id.to_hex()).collect()
}

#[utoipa::path(post, path = "/v1/core/conversations/{conversation_id}/records",
    params(("conversation_id" = String, Path)), request_body = DagAppendRequest,
    responses((status = 200, body = DagAppendResponse), (status = 400, body = ApiErrorEnvelope), (status = 409, body = ApiErrorEnvelope)))]
pub(crate) async fn append_core_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(conversation_id): Path<String>,
    payload: Result<Json<DagAppendRequest>, JsonRejection>,
) -> Result<Json<DagAppendResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    let req = json_payload(payload)?;
    let times = core_entity_timestamps(req.occurred_start, req.occurred_end, req.learned_at)?;
    let body = core_body_for_write(ENTITY_TYPE_TURN, &req.body);
    let appended = server
        .vault
        .append_record(&AppendRecord {
            conversation,
            parent: parse_optional(req.parent.as_deref(), "parent")?,
            advance: req.advance,
            kind: ENTITY_TYPE_TURN,
            occurred: times.occurred,
            learned_at: times.learned_at,
            body: encode_core_body(&body)?,
            text: core_text_fields(req.text.as_deref(), &body),
            session: parse_optional(req.session.as_deref(), "session")?,
            actor: req.actor.parse(&auth)?,
        })
        .map_err(|e| core_engine_error("record append failed", e))?;
    let Json(item) = project_core_entity(&server.vault, &appended.id, View::Full)?;
    Ok(Json(DagAppendResponse {
        entity: CoreEntityWriteResponse {
            id: appended.id.to_hex(),
            entity_type: ENTITY_TYPE_TURN,
            item,
        },
        head: appended.head.map(|id| id.to_hex()),
        parent: appended.parent.map(|id| id.to_hex()),
    }))
}

#[utoipa::path(get, path = "/v1/core/conversations/{conversation_id}/dag",
    params(("conversation_id" = String, Path), DagPageQuery),
    responses((status = 200, body = DagPageResponse), (status = 400, body = ApiErrorEnvelope)))]
pub(crate) async fn get_core_dag(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(conversation_id): Path<String>,
    query: Result<Query<DagPageQuery>, QueryRejection>,
) -> Result<Json<DagPageResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    let req = query_params(query)?;
    let page = server
        .vault
        .main_line(
            &conversation,
            DagPageRequest {
                after: parse_optional(req.after.as_deref(), "after")?,
                limit: req.limit.unwrap_or(100),
            },
        )
        .map_err(|e| core_engine_error("DAG read failed", e))?;
    Ok(Json(DagPageResponse {
        head: page.head.map(|id| id.to_hex()),
        root: page.root.map(|id| id.to_hex()),
        main_line: ids(page.main_line),
        page: DagPageCursor {
            next: page.next.map(|id| id.to_hex()),
        },
    }))
}

#[utoipa::path(post, path = "/v1/core/conversations/{conversation_id}/head",
    params(("conversation_id" = String, Path)), request_body = DagHeadRequest,
    responses((status = 200, body = DagHeadResponse), (status = 400, body = ApiErrorEnvelope)))]
pub(crate) async fn move_core_head(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(conversation_id): Path<String>,
    payload: Result<Json<DagHeadRequest>, JsonRejection>,
) -> Result<Json<DagHeadResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    let record = parse_entity_id_param(&json_payload(payload)?.record, "record")?;
    server
        .vault
        .move_head(&conversation, &record)
        .map_err(|e| core_engine_error("HEAD move failed", e))?;
    Ok(Json(DagHeadResponse {
        head: record.to_hex(),
    }))
}

#[utoipa::path(post, path = "/v1/core/conversations/{conversation_id}/scope",
    params(("conversation_id" = String, Path)), request_body = DagScopeRequest,
    responses((status = 200, body = DagRecordsResponse), (status = 400, body = ApiErrorEnvelope)))]
pub(crate) async fn resolve_core_scope(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(conversation_id): Path<String>,
    payload: Result<Json<DagScopeRequest>, JsonRejection>,
) -> Result<Json<DagRecordsResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    let scope = json_payload(payload)?.parse(conversation)?;
    let resolved = server
        .vault
        .resolve_scope(&scope)
        .map_err(|e| core_engine_error("scope read failed", e))?;
    Ok(Json(DagRecordsResponse {
        records: ids(resolved.records),
    }))
}

#[utoipa::path(post, path = "/v1/core/conversations/{conversation_id}/migrate-dag",
    params(("conversation_id" = String, Path)),
    responses((status = 200, body = DagMigrationResponse), (status = 400, body = ApiErrorEnvelope)))]
pub(crate) async fn migrate_core_dag(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(conversation_id): Path<String>,
) -> Result<Json<DagMigrationResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    let migrated = server
        .vault
        .migrate_conversation_dag(&conversation)
        .map_err(|e| core_engine_error("DAG migration failed", e))?;
    Ok(Json(DagMigrationResponse { migrated }))
}

#[utoipa::path(post, path = "/v1/core/turns/{turn_id}/sub-sessions",
    params(("turn_id" = String, Path)), request_body = DagSpawnRequest,
    responses((status = 200, body = DagSpawnResponse), (status = 400, body = ApiErrorEnvelope)))]
pub(crate) async fn spawn_core_sub_session(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(turn_id): Path<String>,
    payload: Result<Json<DagSpawnRequest>, JsonRejection>,
) -> Result<Json<DagSpawnResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let turn = parse_entity_id_param(&turn_id, "turn_id")?;
    let actor = json_payload(payload)?.actor.parse(&auth)?;
    let session = server
        .vault
        .spawn_sub_session(&turn, actor)
        .map_err(|e| core_engine_error("sub-session spawn failed", e))?;
    Ok(Json(DagSpawnResponse {
        session: session.to_hex(),
    }))
}

#[utoipa::path(get, path = "/v1/core/turns/{turn_id}/sub-sessions",
    params(("turn_id" = String, Path)),
    responses((status = 200, body = DagSessionsResponse), (status = 400, body = ApiErrorEnvelope)))]
pub(crate) async fn list_core_sub_sessions(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(turn_id): Path<String>,
) -> Result<Json<DagSessionsResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let turn = parse_entity_id_param(&turn_id, "turn_id")?;
    let sessions = server
        .vault
        .sub_sessions(&turn)
        .map_err(|e| core_engine_error("sub-session read failed", e))?;
    Ok(Json(DagSessionsResponse {
        sessions: ids(sessions),
    }))
}

#[utoipa::path(post, path = "/v1/core/conversations/{conversation_id}/summaries",
    params(("conversation_id" = String, Path)), request_body = DagSummaryRequest,
    responses((status = 200, body = DagSummaryResponse), (status = 400, body = ApiErrorEnvelope), (status = 409, body = ApiErrorEnvelope)))]
pub(crate) async fn mint_core_scope_summary(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(conversation_id): Path<String>,
    payload: Result<Json<DagSummaryRequest>, JsonRejection>,
) -> Result<Json<DagSummaryResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    let req = json_payload(payload)?;
    let (summary, landed) = server
        .vault
        .mint_and_land_scope_summary(
            &req.scope.parse(conversation)?,
            &req.text,
            req.actor.parse(&auth)?,
            parse_optional(req.land_on.as_deref(), "land_on")?,
            req.as_record,
        )
        .map_err(|e| core_engine_error("scope summary mint failed", e))?;
    Ok(Json(DagSummaryResponse {
        summary: summary.to_hex(),
        claim: landed.as_ref().map(|l| l.claim.to_hex()),
        record: landed.and_then(|l| l.record).map(|id| id.to_hex()),
    }))
}

#[utoipa::path(get, path = "/v1/core/summaries/{summary_id}/covers",
    params(("summary_id" = String, Path)),
    responses((status = 200, body = DagCoversResponse), (status = 400, body = ApiErrorEnvelope)))]
pub(crate) async fn get_core_summary_covers(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(summary_id): Path<String>,
) -> Result<Json<DagCoversResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let summary = parse_entity_id_param(&summary_id, "summary_id")?;
    let covers = server
        .vault
        .scope_summary_covers(&summary)
        .map_err(|e| core_engine_error("summary covers read failed", e))?;
    Ok(Json(DagCoversResponse {
        covers: ids(covers),
    }))
}

#[utoipa::path(get, path = "/v1/core/claims/{claim_id}/drill",
    params(("claim_id" = String, Path)),
    responses((status = 200, body = DagRecordsResponse), (status = 400, body = ApiErrorEnvelope)))]
pub(crate) async fn drill_core_header(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(claim_id): Path<String>,
) -> Result<Json<DagRecordsResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let claim = parse_entity_id_param(&claim_id, "claim_id")?;
    let records = server
        .vault
        .drill(&claim)
        .map_err(|e| core_engine_error("header drill failed", e))?;
    Ok(Json(DagRecordsResponse {
        records: ids(records),
    }))
}
