//! Per-vault usage facts. Wallet and limit policy routes belong to the host.
use super::check_api_auth;
use crate::{
    config::SyncServerConfig,
    error::{ApiError, ApiErrorDetails},
    server::SyncServer,
    usage::{UsageError, UsageEvent, UsageMode, UsageRecordResult, UsageRollup},
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Json,
};
use std::sync::Arc;
#[utoipa::path(post, path = "/v1/usage/events", request_body = UsageEvent,
    responses((status = 200, body = UsageRecordResult), (status = 400, body = ApiError), (status = 401, body = ApiError), (status = 409, body = ApiError)))]
pub(crate) async fn record_usage_event(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Json(event): Json<UsageEvent>,
) -> Result<Json<UsageRecordResult>, ApiError> {
    check_api_auth(&headers, &server)?;
    let mode = usage_mode_for_event(&server.config, &event)?;
    server
        .usage_ledger
        .record_event(event, mode)
        .map(Json)
        .map_err(usage_error)
}
#[utoipa::path(get, path = "/v1/usage/owners/{owner}/vaults/{vault_id}/rollup",
    params(("owner" = String, Path), ("vault_id" = String, Path)),
    responses((status = 200, body = UsageRollup), (status = 400, body = ApiError), (status = 401, body = ApiError), (status = 404, body = ApiError)))]
pub(crate) async fn get_usage_rollup(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Path((owner, vault_id)): Path<(String, String)>,
) -> Result<Json<UsageRollup>, ApiError> {
    check_api_auth(&headers, &server)?;
    server
        .usage_ledger
        .vault_rollup(&owner, &vault_id)
        .map_err(usage_error)?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("usage rollup", Some(&vault_id)))
}
pub(crate) fn usage_mode_for_event(
    config: &SyncServerConfig,
    event: &UsageEvent,
) -> Result<UsageMode, ApiError> {
    if let Some(usage_mode) = config.runtime.usage_mode_for_model(event.model.as_deref()) {
        return Ok(usage_mode);
    }
    if config.runtime.has_model_route_match(event.model.as_deref()) {
        return Err(ApiError::bad_request(
            "usage event model must match an available runtime route with a single debit boundary",
            Some("model"),
        ));
    }

    if let Some(usage_mode) = config.runtime.usage_mode_without_model() {
        return Ok(usage_mode);
    }

    Err(ApiError::bad_request(
        "usage event model is required when runtime routes mix metered and unmetered modes",
        Some("model"),
    ))
}

pub(crate) fn usage_error(error: UsageError) -> ApiError {
    if matches!(error, UsageError::IdempotencyConflict) {
        return ApiError::new(
            "idempotency key conflicts with recorded usage",
            ApiErrorDetails::IdempotencyReplayConflict {
                idempotency_key: None,
            },
            ["Use the original event or a fresh key."],
        );
    }
    if matches!(error, UsageError::Overflow) {
        return ApiError::bad_request("usage amount exceeds supported range", Some("costRates"));
    }
    if let Some(field) = error.field() {
        return ApiError::bad_request(error.to_string(), Some(field));
    }
    ApiError::internal_server_error("usage ledger persistence failed")
}
