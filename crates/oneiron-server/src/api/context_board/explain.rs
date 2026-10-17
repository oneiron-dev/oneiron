//! Explain receipts (OF-278): GET /v1/core/explain/memory/{entity} answers
//! why a memory appeared in the caller's session, and GET
//! /v1/core/explain/gate/{receipt} why a write needed approval. Each answer
//! carries only what the caller may read; anything else is a 404, the same
//! as an unknown id. The verb rows `vault.explain.memory` and
//! `vault.explain.gate` are host doors over the same lookups, answering the
//! same SDK replies, where anything else reads as none.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL, MEMORY_CODE_NOT_FOUND,
    MemoryError, MemoryResult,
};
use oneiron::task_verb::sdk::{
    ExplainGateReply, ExplainGateRequest, ExplainMemoryReply, ExplainMemoryRequest,
};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use super::super::{
    CoreContextPackScoreEvidence, core_engine_error, parse_entity_id_param,
    scoped_read_for_core_auth,
};
use super::{resolved_session_id, session_read_set};
use crate::auth::{CoreAuth, CoreScope};
use crate::error::{ApiError, ApiErrorEnvelope, EnvelopedApiError, ErrorCode};
use crate::server::SyncServer;

/// The session a memory explanation reads.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ExplainMemoryQuery {
    /// The board or pack session that was served the memory. Defaults to
    /// the caller's active session.
    #[serde(default)]
    session_id: Option<String>,
}

/// Why one memory appeared in the caller's session: the OpenAPI mirror of
/// [`ExplainMemoryReply`], which the route answers.
#[derive(ToSchema)]
#[allow(dead_code, reason = "OpenAPI mirror of the SDK reply")]
pub(crate) struct ExplainMemoryResponse {
    /// Hex entity id.
    id: String,
    /// Hex retrieval run that served it, when that run's telemetry persisted.
    #[serde(skip_serializing_if = "Option::is_none")]
    run_id: Option<String>,
    /// 1-based place among the run's primary results.
    #[serde(skip_serializing_if = "Option::is_none")]
    rank: Option<u32>,
    /// Reached as a graph neighbor of a result, not ranked itself.
    neighbor: bool,
    /// The MEMORIES tier a board rendered it at: pinned, snippet or index_only.
    #[serde(skip_serializing_if = "Option::is_none")]
    tier: Option<String>,
    /// `<pack>/<hook>` when a hook block pinned it.
    #[serde(skip_serializing_if = "Option::is_none")]
    hook: Option<String>,
    /// The run's score breakdown for this row alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<CoreContextPackScoreEvidence>,
}

/// One system notice a gate decision raised: the OpenAPI mirror of
/// [`oneiron::task_verb::sdk::ExplainGateNotice`].
#[derive(ToSchema)]
#[allow(dead_code, reason = "OpenAPI mirror of the SDK reply")]
pub(crate) struct ExplainGateNotice {
    /// Notice type token.
    notice_type: String,
    /// Opaque reference to the policy row it cites.
    #[serde(skip_serializing_if = "Option::is_none")]
    row_ref: Option<String>,
}

/// Why a write needed approval: one gate decision as the caller may see it.
/// The OpenAPI mirror of [`ExplainGateReply`], which the route answers.
#[derive(ToSchema)]
#[allow(dead_code, reason = "OpenAPI mirror of the SDK reply")]
pub(crate) struct ExplainGateResponse {
    /// `gate:<hex>` receipt id.
    receipt_id: String,
    /// When the gate decided, Unix seconds.
    decided_at: u64,
    /// allow, pending or deny.
    outcome: String,
    /// Engine reason codes.
    reason_codes: Vec<String>,
    /// The policy rows and checks behind the outcome, by opaque reference.
    receipt_reasons: Vec<String>,
    /// System notices the decision raised.
    notices: Vec<ExplainGateNotice>,
    /// The writer's actor class.
    actor_class: String,
    /// Hex writer, when the caller is it, is the owner, or may read it.
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_ref: Option<String>,
    /// What kind of write it was.
    content_kind: String,
    /// The policy manifest version it was decided under.
    policy_manifest_version: String,
    /// Hex claim the write proposed, when the caller may read it.
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_ref: Option<String>,
}

/// Why a memory appeared in the caller's session: the run that served it and
/// its place there, the board tier it rode, and the run's score breakdown
/// for it. Only a memory the session was served and the caller still reads.
#[utoipa::path(
    get,
    path = "/v1/core/explain/memory/{entity}",
    params(
        ("entity" = String, Path, description = "Hex entity id of the memory"),
        ExplainMemoryQuery
    ),
    responses(
        (status = 200, description = "Why the memory appeared.", body = ExplainMemoryResponse, content_type = "application/json"),
        (status = 400, description = "Malformed entity or session id.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "The session was not served this memory, or the caller cannot read it.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Explanation failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_explain_memory(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(entity): Path<String>,
    Query(query): Query<ExplainMemoryQuery>,
) -> Result<Json<ExplainMemoryReply>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    let Some(explained) =
        explained_memory(&server, &auth, &entity, query.session_id.as_deref()).await?
    else {
        return Err(ApiError::not_found("served memory", Some(&entity)).into());
    };
    Ok(Json(explained))
}

/// Why `entity` appeared in the caller's session `session` (its active one
/// when absent), read under the caller's own scoped read: the lookup the
/// route and `vault.explain.memory` share. `None` when the session was not
/// served it or the caller cannot read it now.
async fn explained_memory(
    server: &SyncServer,
    auth: &CoreAuth,
    entity: &str,
    session: Option<&str>,
) -> Result<Option<ExplainMemoryReply>, ApiError> {
    let id = parse_entity_id_param(entity, "entity")?;
    let read = scoped_read_for_core_auth(&server.vault, auth)?;
    let caller = auth.principal_ref().unwrap_or(auth.principal()).trim();
    let session = resolved_session_id(server, caller, session).await?;
    let explained = match session_read_set(server, caller, session.as_deref()).await? {
        Some(reads) => server
            .vault
            .explain_served_memory(&read, &reads, id)
            .map_err(|error| core_engine_error("memory explanation failed", error))?,
        None => None,
    };
    Ok(explained.map(ExplainMemoryReply::from))
}

/// Why a write needed approval: the gate decision behind receipt
/// `gate:<hex>`, its outcome, reason codes and the policy rows it cites by
/// reference. Only for the writer, the owner, or a caller that may read the
/// claim the write proposed.
#[utoipa::path(
    get,
    path = "/v1/core/explain/gate/{receipt}",
    params(("receipt" = String, Path, description = "Gate receipt id, gate:<hex>")),
    responses(
        (status = 200, description = "Why the write was decided as it was.", body = ExplainGateResponse, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "No such gate receipt, or the caller may not read it.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Explanation failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_explain_gate(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(receipt): Path<String>,
) -> Result<Json<ExplainGateReply>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    let Some(explained) = explained_gate(&server, &auth, &receipt)? else {
        return Err(ApiError::not_found("gate receipt", Some(&receipt)).into());
    };
    Ok(Json(explained))
}

/// The gate decision behind `receipt`, as the caller may see it: the lookup
/// the route and `vault.explain.gate` share. `None` for no such receipt, or
/// one the caller may not read.
fn explained_gate(
    server: &SyncServer,
    auth: &CoreAuth,
    receipt: &str,
) -> Result<Option<ExplainGateReply>, ApiError> {
    let read = scoped_read_for_core_auth(&server.vault, auth)?;
    Ok(server
        .vault
        .explain_gate_receipt(&read, receipt)
        .map_err(|error| core_engine_error("gate explanation failed", error))?
        .map(ExplainGateReply::from))
}

/// `vault.explain.memory`: why a memory appeared in the caller's session,
/// from the lookup GET /v1/core/explain/memory/{entity} takes. A memory the
/// session was not served, or the caller cannot read, reads as none.
pub(crate) async fn vault_explain_memory(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ExplainMemoryRequest,
) -> MemoryResult<Option<ExplainMemoryReply>> {
    explained_memory(server, auth, &input.entity, input.session_id.as_deref())
        .await
        .map_err(explain_refusal)
}

/// `vault.explain.gate`: why a write needed approval, from the lookup GET
/// /v1/core/explain/gate/{receipt} takes. A receipt the caller may not
/// read reads as none.
pub(crate) async fn vault_explain_gate(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ExplainGateRequest,
) -> MemoryResult<Option<ExplainGateReply>> {
    explained_gate(server, auth, &input.receipt).map_err(explain_refusal)
}

/// A lookup's refusal in the facade's vocabulary: its code picks the memory
/// code, its message and suggestions pass through.
fn explain_refusal(error: ApiError) -> MemoryError {
    let code = match error.code() {
        ErrorCode::BadRequest => MEMORY_CODE_BAD_REQUEST,
        ErrorCode::Unauthorized | ErrorCode::Forbidden => MEMORY_CODE_FORBIDDEN,
        ErrorCode::NotFound => MEMORY_CODE_NOT_FOUND,
        _ => MEMORY_CODE_INTERNAL,
    };
    let suggestions: Vec<&str> = error.suggestions().iter().map(String::as_str).collect();
    MemoryError::new(code, error.message(), &suggestions)
}
