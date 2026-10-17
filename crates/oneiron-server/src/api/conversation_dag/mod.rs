//! HTTP adapters for transactional conversation DAG and summary doors.
//!
//! The DAG ledger is read raw, under no credential key, so every read here
//! refuses a credential narrowed to some records: its records cannot bound
//! the ids that come back.

mod summary;
mod types;
use super::{
    CoreEntityWriteResponse, core_body_for_write, core_engine_error, core_entity_timestamps,
    core_text_fields, core_write_text, encode_core_body, json_payload, parse_entity_id_param,
    project_core_entity, query_params,
};
use crate::auth::{CoreAuth, CoreScope};
use crate::error::{ApiError, ApiErrorEnvelope, EnvelopedApiError};
use crate::projection::View;
use crate::server::SyncServer;
use axum::Json;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{Extensions, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use oneiron::conversation_dag::{AddressMode, AppendRecord, DagPageRequest, QuoteSpan};
use oneiron::core_write::{
    CoreDagAddressMode, CoreDagQuoteInput, DagRecordAppendInput, DagRecordAppendReceipt,
};
use oneiron::memory::MemoryError;
use oneiron::reaction::{MessageReactionExternal, MessageReactionReceipt, MessageReactionRequest};
use oneiron::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use oneiron::scope_summary::{ScopeSummaryRequest, ScopeSummaryTarget};
use oneiron::task_verb::sdk::AgentVerb;
use oneiron::{EdgeKind, EntityId};
use std::sync::Arc;
pub(crate) use summary::*;
use types::parse_optional;
pub(crate) use types::*;

fn ids(records: Vec<EntityId>) -> Vec<String> {
    records.into_iter().map(|id| id.to_hex()).collect()
}

fn appended_response(
    server: &SyncServer,
    appended: oneiron::conversation_dag::AppendedRecord,
) -> Result<Json<DagAppendResponse>, EnvelopedApiError> {
    server.ai.turn_landed(
        server.vault(),
        oneiron::dreamer_wake::WakeTurnSubject::Vault,
    );
    project_appended(server, appended.into())
}

/// An append's 200 body: the stored TURN, HEAD after it and its parent.
/// It lands nothing; the write that made the record did.
fn project_appended(
    server: &SyncServer,
    receipt: DagRecordAppendReceipt,
) -> Result<Json<DagAppendResponse>, EnvelopedApiError> {
    let id = parse_entity_id_param(&receipt.id, "id")?;
    let Json(item) = project_core_entity(&server.vault, &id, View::Full)?;
    Ok(Json(DagAppendResponse {
        entity: CoreEntityWriteResponse {
            id: receipt.id,
            entity_type: ENTITY_TYPE_TURN,
            item,
        },
        head: receipt.head,
        parent: receipt.parent,
    }))
}

/// A DAG or core write's refusal: the adapter's own, or the engine door's,
/// forwarded whole as the facade forwards it (an invented reference is a
/// 422).
pub(crate) enum DagWriteError {
    Core(EnvelopedApiError),
    Memory(super::facade::FacadeApiError),
}

impl From<ApiError> for DagWriteError {
    fn from(error: ApiError) -> Self {
        Self::Core(error.into())
    }
}

impl From<EnvelopedApiError> for DagWriteError {
    fn from(error: EnvelopedApiError) -> Self {
        Self::Core(error)
    }
}

impl From<super::facade::FacadeApiError> for DagWriteError {
    fn from(error: super::facade::FacadeApiError) -> Self {
        Self::Memory(error)
    }
}

impl From<MemoryError> for DagWriteError {
    fn from(error: MemoryError) -> Self {
        Self::Memory(error.into())
    }
}

impl IntoResponse for DagWriteError {
    fn into_response(self) -> Response {
        match self {
            Self::Core(error) => error.into_response(),
            Self::Memory(error) => error.into_response(),
        }
    }
}

fn append_input(
    conversation: EntityId,
    req: DagAppendRequest,
    auth: &CoreAuth,
) -> Result<AppendRecord, EnvelopedApiError> {
    let times = core_entity_timestamps(req.occurred_start, req.occurred_end, req.learned_at)?;
    let body = core_body_for_write(ENTITY_TYPE_TURN, &req.body);
    Ok(AppendRecord {
        conversation,
        reply_to: parse_optional(req.reply_to.as_deref(), "reply_to")?,
        quote: req
            .quote
            .as_ref()
            .map(|quote| {
                Ok::<_, ApiError>(QuoteSpan {
                    message: parse_entity_id_param(&quote.message, "quote.message")?,
                    start: quote.start,
                    end: quote.end,
                })
            })
            .transpose()?,
        address: match req.addr.unwrap_or(DagAddressMode::Broadcast) {
            DagAddressMode::Broadcast => AddressMode::Broadcast,
            DagAddressMode::Direct => AddressMode::Direct,
        },
        recipients: req
            .to
            .unwrap_or_default()
            .iter()
            .map(|id| parse_entity_id_param(id, "to"))
            .collect::<Result<Vec<_>, _>>()?,
        parent: parse_optional(req.parent.as_deref(), "parent")?,
        advance: req.advance,
        kind: ENTITY_TYPE_TURN,
        occurred: times.occurred,
        learned_at: times.learned_at,
        body: encode_core_body(&body)?,
        text: core_text_fields(req.text.as_deref(), &body),
        session: parse_optional(req.session.as_deref(), "session")?,
        actor: req.actor.parse(auth)?,
        thread_audience: req
            .thread_audience
            .map(|ids| {
                ids.iter()
                    .map(|id| parse_entity_id_param(id, "thread_audience"))
                    .collect::<Result<std::collections::BTreeSet<_>, _>>()
            })
            .transpose()?,
    })
}

#[utoipa::path(post, path = "/v1/core/conversations/{conversation_id}/records",
    params(("conversation_id" = String, Path)), request_body = DagAppendRequest,
    responses((status = 200, body = DagAppendResponse), (status = 400, body = ApiErrorEnvelope),
        (status = 403, description = "The writer's standing is refused: the engine's FORBIDDEN, as the facade's MemoryError body. A credential without core:write is refused in the core envelope before the engine runs.", body = super::facade::MemoryErrorEnvelopeSchema),
        (status = 409, description = "The conversation or its HEAD is not in a state this append takes: the engine's INVALID_STATE, as the facade's MemoryError body.", body = super::facade::MemoryErrorEnvelopeSchema),
        (status = 422, description = "A ref the write names does not resolve for its writer: INVENTED_REFERENCE, naming the field pointer, as the facade's MemoryError body.", body = super::facade::MemoryErrorEnvelopeSchema)))]
pub(crate) async fn append_core_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(conversation_id): Path<String>,
    headers: HeaderMap,
    extensions: Extensions,
    payload: Result<Json<DagAppendRequest>, JsonRejection>,
) -> Result<Json<DagAppendResponse>, DagWriteError> {
    auth.require(CoreScope::Write)?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    let req = json_payload(payload)?;
    // The route's own refusals first: the actor its body binds, and its
    // interval.
    let actor = req.actor.parse(&auth)?;
    core_entity_timestamps(req.occurred_start, req.occurred_end, req.learned_at)?;
    let input = append_row(conversation, req);
    // OF-181: `vault.conversations.records.append`, as an action when the
    // credential binds one that writes as this actor, else through the
    // row's own door as the actor the body bound. Either lands the turn
    // once.
    let receipt =
        match super::facade::action_routes::rest_action_bound(&server, &auth, &headers, &input)? {
            Some(bound) if bound.writes_as() == actor => {
                let row = AgentVerb::VaultConversationsRecordsAppend;
                let key =
                    super::facade::action_routes::rest_action_key(&server, &auth, &headers, row)?;
                let output = super::facade::action_routes::execute_facade_row(
                    &server, headers, extensions, bound, row, &input, key,
                )
                .await?;
                serde_json::from_value::<DagRecordAppendReceipt>(output)
                    .map_err(|_| ApiError::internal_server_error("append result encoding failed"))?
            }
            _ => super::facade::host_doors::write_dag_record(&server, &auth, actor, &input)?,
        };
    Ok(project_appended(&server, receipt)?)
}

/// The append row's input: the request less its actor, which the route
/// asserts and the writer bylines.
fn append_row(conversation: EntityId, req: DagAppendRequest) -> DagRecordAppendInput {
    DagRecordAppendInput {
        conversation: conversation.to_hex(),
        parent: req.parent,
        reply_to: req.reply_to,
        addr: req.addr.map(|addr| match addr {
            DagAddressMode::Broadcast => CoreDagAddressMode::Broadcast,
            DagAddressMode::Direct => CoreDagAddressMode::Direct,
        }),
        to: req.to,
        advance: req.advance,
        body: req.body,
        text: core_write_text(req.text),
        occurred_start: req.occurred_start,
        occurred_end: req.occurred_end,
        learned_at: req.learned_at,
        session: req.session,
        quote: req.quote.map(|quote| CoreDagQuoteInput {
            message: quote.message,
            start: quote.start,
            end: quote.end,
        }),
        thread_audience: req.thread_audience,
    }
}

/// `ids` less those `auth`'s own read withholds: the DAG ledger is read raw,
/// so a private thread's records (FIX 2951) leave here, as hex.
fn readable_ids(
    server: &SyncServer,
    auth: &CoreAuth,
    ids: Vec<EntityId>,
) -> Result<Vec<String>, EnvelopedApiError> {
    let read = crate::api::scoped_read_for_core_auth(&server.vault, auth)?;
    let mut kept = Vec::with_capacity(ids.len());
    for id in ids {
        if read
            .is_entity_readable(&id)
            .map_err(|e| core_engine_error("record access failed", e))?
        {
            kept.push(id.to_hex());
        }
    }
    Ok(kept)
}

/// Refuses a `record` `auth`'s own read withholds as the missing record it
/// reads as (FIX 2951).
fn require_readable_record(
    server: &SyncServer,
    auth: &CoreAuth,
    record: EntityId,
) -> Result<(), EnvelopedApiError> {
    let read = crate::api::scoped_read_for_core_auth(&server.vault, auth)?;
    if read
        .is_entity_readable(&record)
        .map_err(|e| core_engine_error("record access failed", e))?
    {
        Ok(())
    } else {
        Err(ApiError::not_found("conversation record", Some(&record.to_hex())).into())
    }
}

#[utoipa::path(get, path = "/v1/core/conversations/{conversation_id}/records",
    params(("conversation_id" = String, Path), DagPageQuery),
    responses((status = 200, body = DagPageResponse), (status = 400, body = ApiErrorEnvelope)))]
pub(crate) async fn get_core_dag(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(conversation_id): Path<String>,
    query: Result<Query<DagPageQuery>, QueryRejection>,
) -> Result<Json<DagPageResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    let req = query_params(query)?;
    if req
        .with
        .as_deref()
        .is_some_and(|with| with != "thread_meta" && with != "reactions")
    {
        return Err(ApiError::bad_request("unsupported records projection", None).into());
    }
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
    let thread_meta = if req.with.as_deref() == Some("thread_meta") {
        // Each trunk's line counts only the replies this caller reads.
        let read = crate::api::scoped_read_for_core_auth(&server.vault, &auth)?;
        let mut meta = std::collections::BTreeMap::new();
        for id in &page.main_line {
            let value = server
                .vault
                .thread_meta_under(&read, *id)
                .map_err(|e| core_engine_error("thread metadata read failed", e))?
                .map(|row| DagThreadMetaResponse {
                    root: row.root.to_hex(),
                    count: row.count,
                    last_at: row.last_at,
                });
            meta.insert(id.to_hex(), value);
        }
        Some(meta)
    } else {
        None
    };
    let (records, reactions_outbound) = if req.with.as_deref() == Some("reactions") {
        let viewer = req.viewer.as_deref().ok_or_else(|| {
            ApiError::bad_request("viewer is required with reactions", Some("viewer"))
        })?;
        let (records, outbound) =
            reaction_records(&server, &auth, conversation, &page.main_line, viewer)?;
        (Some(records), Some(outbound))
    } else {
        (None, None)
    };
    Ok(Json(DagPageResponse {
        head: page.head.map(|id| id.to_hex()),
        thread_meta,
        records,
        reactions_outbound,
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
    auth.require_unrestricted_record_scope()?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    let scope = json_payload(payload)?.parse(conversation)?;
    let resolved = server
        .vault
        .resolve_dag_scope(&scope)
        .map_err(|e| core_engine_error("scope read failed", e))?;
    Ok(Json(DagRecordsResponse {
        records: readable_ids(&server, &auth, resolved.records)?,
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
        .spawn_dag_sub_session(&turn, actor)
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
    auth.require_unrestricted_record_scope()?;
    let turn = parse_entity_id_param(&turn_id, "turn_id")?;
    let sessions = server
        .vault
        .sub_sessions(&turn)
        .map_err(|e| core_engine_error("sub-session read failed", e))?;
    Ok(Json(DagSessionsResponse {
        sessions: ids(sessions),
    }))
}

/// Queues a declared summary for the Dreamer, which alone writes the body
/// (ARCH-0006a). Refused up front when no Dreamer here writes summaries.
fn declare_summary(
    server: &SyncServer,
    request: &ScopeSummaryRequest,
    purpose: Option<&str>,
) -> Result<(StatusCode, Json<DagSummaryQueuedResponse>), EnvelopedApiError> {
    server
        .ai
        .summary_writer()
        .map_err(ApiError::summary_writer_unavailable)?;
    let queued = match purpose {
        Some(purpose) => server.vault.request_scope_summary_for(request, purpose),
        None => server.vault.request_scope_summary(request),
    }
    .map_err(|e| core_engine_error("summary declaration failed", e))?;
    server.ai.attempt_queued();
    Ok((StatusCode::ACCEPTED, Json(summary::queued_response(queued))))
}

#[utoipa::path(post, path = "/v1/core/conversations/{conversation_id}/summaries",
    params(("conversation_id" = String, Path)), request_body = DagSummaryRequest,
    responses((status = 202, body = DagSummaryQueuedResponse), (status = 400, body = ApiErrorEnvelope), (status = 409, body = ApiErrorEnvelope), (status = 503, body = ApiErrorEnvelope)))]
pub(crate) async fn mint_core_scope_summary(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(conversation_id): Path<String>,
    payload: Result<Json<DagSummaryRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<DagSummaryQueuedResponse>), EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    let req = json_payload(payload)?;
    let scope = req.scope.parse(conversation)?;
    // A summary is queued only over records this caller reads (FIX 2951).
    let resolved = server
        .vault
        .resolve_dag_scope(&scope)
        .map_err(|e| core_engine_error("scope read failed", e))?;
    for record in &resolved.records {
        require_readable_record(&server, &auth, *record)?;
    }
    let request = ScopeSummaryRequest {
        target: ScopeSummaryTarget::Scope {
            scope,
            land_on: parse_optional(req.land_on.as_deref(), "land_on")?,
            as_record: req.as_record,
        },
        requester: req.actor.parse(&auth)?,
    };
    declare_summary(&server, &request, req.purpose.as_deref())
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
    auth.require_unrestricted_record_scope()?;
    let summary = parse_entity_id_param(&summary_id, "summary_id")?;
    let covers = server
        .vault
        .scope_summary_covers(&summary)
        .map_err(|e| core_engine_error("summary covers read failed", e))?;
    Ok(Json(DagCoversResponse {
        covers: readable_ids(&server, &auth, covers)?,
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
    auth.require_unrestricted_record_scope()?;
    let claim = parse_entity_id_param(&claim_id, "claim_id")?;
    let records = server
        .vault
        .drill(&claim)
        .map_err(|e| core_engine_error("header drill failed", e))?;
    Ok(Json(DagRecordsResponse {
        records: readable_ids(&server, &auth, records)?,
    }))
}

#[utoipa::path(post, path = "/v1/core/conversations/{conversation_id}/records/{record}/thread",
    params(("conversation_id" = String, Path), ("record" = String, Path)), request_body = DagAppendRequest,
    responses((status = 200, body = DagAppendResponse), (status = 400, body = ApiErrorEnvelope),
        (status = 403, description = "The writer's standing is refused: the engine's FORBIDDEN, as the facade's MemoryError body. A credential without core:write is refused in the core envelope before the engine runs.", body = super::facade::MemoryErrorEnvelopeSchema),
        (status = 409, description = "The thread or its conversation is not in a state this reply takes: the engine's INVALID_STATE, as the facade's MemoryError body.", body = super::facade::MemoryErrorEnvelopeSchema),
        (status = 422, description = "A ref the reply names does not resolve for its writer: INVENTED_REFERENCE, naming the field pointer, as the facade's MemoryError body.", body = super::facade::MemoryErrorEnvelopeSchema)))]
pub(crate) async fn reply_in_thread(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((conversation_id, record)): Path<(String, String)>,
    payload: Result<Json<DagAppendRequest>, JsonRejection>,
) -> Result<Json<DagAppendResponse>, DagWriteError> {
    auth.require(CoreScope::Write)?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    let record = parse_entity_id_param(&record, "record")?;
    let req = json_payload(payload)?;
    if req.advance || req.parent.is_some() || req.reply_to.is_some() {
        return Err(ApiError::bad_request(
            "thread replies select their own parent and do not advance HEAD",
            None,
        )
        .into());
    }
    let input = append_input(conversation, req, &auth)?;
    let writer = super::credential_memory(
        &server.vault,
        Some(&auth),
        input.actor.entity_ref(),
        input.actor.actor_class(),
    )
    .at(auth.locality());
    let appended = server.vault.reply_in_thread(&writer, record, &input)?;
    Ok(appended_response(&server, appended)?)
}

#[utoipa::path(get, path = "/v1/core/conversations/{conversation_id}/records/{record}/thread",
    params(("conversation_id" = String, Path), ("record" = String, Path)),
    responses((status = 200, body = DagThreadResponse), (status = 400, body = ApiErrorEnvelope)))]
pub(crate) async fn get_thread(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((conversation_id, record)): Path<(String, String)>,
) -> Result<Json<DagThreadResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    let record = parse_entity_id_param(&record, "record")?;
    // The raw ledger is read under the caller's own read: a private thread
    // (FIX 2951) it is off is no thread, and a branch it is off no record.
    require_readable_record(&server, &auth, record)?;
    let read = crate::api::scoped_read_for_core_auth(&server.vault, &auth)?;
    let (thread, roots) = server
        .vault
        .thread_under(&read, record)
        .map_err(|e| core_engine_error("thread read failed", e))?;
    if thread.conversation != conversation {
        return Err(ApiError::not_found("conversation record", Some(&record.to_hex())).into());
    }
    Ok(Json(DagThreadResponse {
        roots: ids(roots),
        root: thread.root.map(|id| id.to_hex()),
        replies: ids(thread.replies),
        count: thread.count,
        last_at: thread.last_at,
    }))
}

#[utoipa::path(post, path = "/v1/core/conversations/{conversation_id}/records/{record}/thread/summary",
    params(("conversation_id" = String, Path), ("record" = String, Path)), request_body = DagThreadSummaryRequest,
    responses((status = 202, body = DagSummaryQueuedResponse), (status = 400, body = ApiErrorEnvelope), (status = 503, body = ApiErrorEnvelope)))]
pub(crate) async fn summarize_thread(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path((conversation_id, record)): Path<(String, String)>,
    payload: Result<Json<DagThreadSummaryRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<DagSummaryQueuedResponse>), EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    let record = parse_entity_id_param(&record, "record")?;
    let req = json_payload(payload)?;
    require_readable_record(&server, &auth, record)?;
    let thread = server
        .vault
        .thread(record)
        .map_err(|e| core_engine_error("thread read failed", e))?;
    if thread.conversation != conversation {
        return Err(ApiError::not_found("conversation record", Some(&record.to_hex())).into());
    }
    // The summary covers the thread the door selects: one this caller is
    // off (FIX 2951) is no thread to summarize.
    if let Some(root) = thread.root {
        require_readable_record(&server, &auth, root)?;
    }
    let request = ScopeSummaryRequest {
        target: ScopeSummaryTarget::Thread { trunk: record },
        requester: req.actor.parse(&auth)?,
    };
    declare_summary(&server, &request, req.purpose.as_deref())
}

#[utoipa::path(get, path = "/v1/core/conversations/{conversation_id}/canonical",
    params(("conversation_id" = String, Path)),
    responses((status = 200, body = DagRecordsResponse), (status = 400, body = ApiErrorEnvelope)))]
pub(crate) async fn get_canonical(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(conversation_id): Path<String>,
) -> Result<Json<DagRecordsResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    let conversation = parse_entity_id_param(&conversation_id, "conversation_id")?;
    let resolved = server
        .vault
        .resolve_dag_scope(&oneiron::conversation_dag::ScopeSelector {
            conversation,
            session: None,
            path: oneiron::conversation_dag::ScopePath::Canonical,
            include_forks: false,
        })
        .map_err(|e| core_engine_error("canonical read failed", e))?;
    Ok(Json(DagRecordsResponse {
        records: readable_ids(&server, &auth, resolved.records)?,
    }))
}

/// Grouped pills for each listed TURN and the MESSAGEs beneath it, in one
/// engine snapshot, for a viewer the credential may speak for.
fn reaction_records(
    server: &SyncServer,
    auth: &CoreAuth,
    conversation: EntityId,
    main_line: &[EntityId],
    viewer: &str,
) -> Result<(Vec<DagReactionRecord>, &'static str), EnvelopedApiError> {
    if !auth.is_owner_grade() && auth.principal_ref() != Some(viewer) {
        return Err(ApiError::forbidden_scope("viewer").into());
    }
    let viewer = parse_entity_id_param(viewer, "viewer")?;
    let mut pairs = Vec::new();
    for turn in main_line {
        let children = server
            .vault
            .sources(turn, EdgeKind::PartOf, Some(ENTITY_TYPE_MESSAGE))
            .map_err(|e| core_engine_error("message listing failed", e))?;
        for target in std::iter::once(*turn).chain(children.iter().copied()) {
            if auth
                .can_read_entity(&server.vault, &target)
                .map_err(|e| core_engine_error("record access failed", e))?
            {
                pairs.push((*turn, target, target == *turn && !children.is_empty()));
            }
        }
    }
    let targets: Vec<EntityId> = pairs.iter().map(|(_, target, _)| *target).collect();
    // A credential reads each reaction under its own key, as it reads the
    // record; the server's own secret reads them all.
    let pills = match auth.verified_slip() {
        Some(_) => crate::api::scoped_read_for_core_auth(&server.vault, auth)?
            .reaction_pills(&targets, viewer),
        None => server.vault.reaction_pills(&targets, viewer),
    }
    .map_err(|e| core_engine_error("reaction listing failed", e))?;
    let records = pairs
        .into_iter()
        .filter_map(|(turn, target, groups_children)| {
            let groups = pills.get(&target)?;
            // A witnessed TURN groups MESSAGE children: list it only when it
            // was reacted to itself. A first-party append is its own record.
            if groups_children && groups.is_empty() {
                return None;
            }
            Some(DagReactionRecord {
                turn: turn.to_hex(),
                id: target.to_hex(),
                reactions: groups
                    .iter()
                    .map(|pill| DagReactionPill {
                        glyph: pill.glyph.clone(),
                        count: pill.count,
                        by: pill.by.iter().map(EntityId::to_hex).collect(),
                        mine: pill.mine,
                    })
                    .collect(),
            })
        })
        .collect();
    let outbound = server
        .vault
        .reactions_outbound(conversation)
        .map_err(|e| core_engine_error("room reaction posture failed", e))?;
    Ok((records, outbound))
}

/// Puts or removes one reaction on a MESSAGE or TURN through the
/// `vault.messages.react` row (OF-181): a credential an action binds runs it
/// as that action, as the app's button does; an owner-grade credential that
/// names no principal writes through the row's own door as the actor its
/// body binds. The vault revalidates the person and the room audience in
/// its write transaction.
#[utoipa::path(post, path = "/v1/core/messages/{message}/reactions",
    params(("message" = String, Path)), request_body = ReactionRequest,
    responses((status = 200, body = ReactionResponse), (status = 400, body = ApiErrorEnvelope),
        (status = 403, body = ApiErrorEnvelope)))]
pub(crate) async fn react_core_message(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(message): Path<String>,
    headers: HeaderMap,
    extensions: Extensions,
    payload: Result<Json<ReactionRequest>, JsonRejection>,
) -> Result<Json<ReactionResponse>, DagWriteError> {
    auth.require(CoreScope::Write)?;
    let message = parse_entity_id_param(&message, "message")?;
    let req = json_payload(payload)?;
    let by = parse_entity_id_param(&req.by, "by")?;
    let actor = req.actor.parse(&auth)?;
    if let Some(external) = &req.external {
        // Connector ingress: the host resolved the provider's identities, and
        // the engine's mirror MACHINE writes the claim.
        if !auth.is_owner_grade() {
            return Err(ApiError::forbidden_scope("reaction_external").into());
        }
        if let Some(origin) = &external.origin {
            parse_entity_id_param(origin, "external.origin")?;
        }
        if !matches!(
            (
                req.remove,
                external.origin.is_some(),
                req.occurred_at.is_some()
            ),
            (true, false, _) | (false, true, _) | (false, false, true)
        ) {
            return Err(ApiError::bad_request(
                "a provider add needs occurred_at, an echo origin, a removal neither",
                Some("external"),
            )
            .into());
        }
    } else {
        if actor.entity_ref() != by {
            return Err(ApiError::forbidden_scope("reaction_actor").into());
        }
        if !req.remove && req.occurred_at.is_none() {
            return Err(
                ApiError::bad_request("occurred_at is required", Some("occurred_at")).into(),
            );
        }
    }
    let input = MessageReactionRequest {
        message: message.to_hex(),
        by: by.to_hex(),
        glyph: req.glyph,
        occurred_at: req.occurred_at,
        remove: req.remove,
        external: req.external.map(|external| MessageReactionExternal {
            connector: external.connector,
            id: external.id,
            origin: external.origin,
        }),
    };
    let receipt = match super::facade::action_routes::action_bound(&server, &auth)? {
        Some(bound) => {
            let row = AgentVerb::VaultMessagesReact;
            let key = super::facade::action_routes::rest_action_key(&server, &auth, &headers, row)?;
            let output = super::facade::action_routes::execute_facade_row(
                &server, headers, extensions, bound, row, &input, key,
            )
            .await?;
            serde_json::from_value::<MessageReactionReceipt>(output)
                .map_err(|_| ApiError::internal_server_error("reaction result encoding failed"))?
        }
        None => {
            super::facade::host_doors::react_message(&server, &auth, Some(actor), input).await?
        }
    };
    Ok(Json(ReactionResponse {
        id: receipt.id,
        event: receipt.event,
    }))
}
