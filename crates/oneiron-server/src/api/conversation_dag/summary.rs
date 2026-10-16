//! Scope-summary result polling, retained metadata and explicit re-derivation.

use super::*;

#[utoipa::path(get, path = "/v1/core/summary-attempts/{attempt}",
    params(("attempt" = String, Path)),
    responses((status = 200, body = DagSummaryStatusResponse), (status = 404, body = ApiErrorEnvelope)))]
pub(crate) async fn get_core_summary_status(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(attempt): Path<String>,
) -> Result<Json<DagSummaryStatusResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    let attempt = crate::api::run_tree::parse_attempt_id_param(&attempt, "attempt")?;
    let status = server
        .vault
        .scope_summary_status(attempt)
        .map_err(|error| core_engine_error("summary status read failed", error))?;
    if !auth.is_owner_grade() && auth.principal_ref() != Some(status.requester.as_str()) {
        return Err(ApiError::not_found("summary declaration", None).into());
    }
    Ok(Json(DagSummaryStatusResponse {
        attempt: status.attempt,
        current_attempt: status.current_attempt,
        state: status.state,
        result: status.result.map(|result| DagSummaryResultResponse {
            summary: result.summary,
            claim: result.claim,
            record: result.record,
        }),
        failure: status.failure,
        retry_at: status.retry_at,
        updated_at: status.updated_at,
    }))
}

#[utoipa::path(post, path = "/v1/core/summaries/{summary_id}/rederive",
    params(("summary_id" = String, Path)), request_body = DagSpawnRequest,
    responses((status = 202, body = DagSummaryQueuedResponse), (status = 503, body = ApiErrorEnvelope)))]
pub(crate) async fn rederive_core_scope_summary(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(summary_id): Path<String>,
    payload: Result<Json<DagSpawnRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<DagSummaryQueuedResponse>), EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    auth.require_unrestricted_record_scope()?;
    server
        .ai
        .summary_writer()
        .map_err(ApiError::summary_writer_unavailable)?;
    let summary = parse_entity_id_param(&summary_id, "summary_id")?;
    if !auth
        .can_read_entity(&server.vault, &summary)
        .map_err(|error| core_engine_error("summary access failed", error))?
    {
        return Err(ApiError::not_found("summary", Some(&summary_id)).into());
    }
    let actor = json_payload(payload)?.actor.parse(&auth)?;
    let queued = server
        .vault
        .rederive_scope_summary(summary, actor)
        .map_err(|error| core_engine_error("summary re-derivation failed", error))?;
    server.ai.attempt_queued();
    Ok((StatusCode::ACCEPTED, Json(queued_response(queued))))
}

#[utoipa::path(get, path = "/v1/core/summaries/{summary_id}/derivation",
    params(("summary_id" = String, Path)),
    responses((status = 200, body = DagSummaryMetadataResponse)))]
pub(crate) async fn get_core_summary_metadata(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(summary_id): Path<String>,
) -> Result<Json<DagSummaryMetadataResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    let summary = parse_entity_id_param(&summary_id, "summary_id")?;
    if !auth
        .can_read_entity(&server.vault, &summary)
        .map_err(|error| core_engine_error("summary access failed", error))?
    {
        return Err(ApiError::not_found("summary", Some(&summary_id)).into());
    }
    let metadata = server
        .vault
        .scope_summary_metadata(&summary)
        .map_err(|error| core_engine_error("summary metadata read failed", error))?;
    let metadata = serde_json::to_value(metadata)
        .map_err(|_| ApiError::bad_request("summary metadata encoding failed", None))?;
    Ok(Json(DagSummaryMetadataResponse { metadata }))
}

#[utoipa::path(get, path = "/v1/core/summary-purposes",
    responses((status = 200, body = Vec<DagSummaryPurposeResponse>)))]
pub(crate) async fn list_core_summary_purposes(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<Vec<DagSummaryPurposeResponse>>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let rows = server
        .vault
        .summary_purposes()
        .map_err(|error| core_engine_error("summary purpose read failed", error))?;
    Ok(Json(
        rows.into_iter()
            .map(|row| DagSummaryPurposeResponse {
                id: row.id,
                description: row.description,
            })
            .collect(),
    ))
}

pub(super) fn queued_response(
    queued: oneiron::scope_summary::ScopeSummaryQueued,
) -> DagSummaryQueuedResponse {
    let attempt: String = queued
        .attempt
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    DagSummaryQueuedResponse {
        status: format!("/v1/core/summary-attempts/{attempt}"),
        attempt,
        coalesced: queued.coalesced,
    }
}
