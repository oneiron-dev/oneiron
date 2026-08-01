use super::check_api_auth;
use super::json_payload;
use super::query_params;
use crate::config::SyncServerConfig;
use crate::error::ApiError;
use crate::error::ApiErrorDetails;
use crate::server::SyncServer;
use crate::usage::ConsumerTopUpRequest;
use crate::usage::ConsumerTopUpState;
use crate::usage::ConsumerUsageDetails;
use crate::usage::ConsumerUsageState;
use crate::usage::UsageError;
use crate::usage::UsageEvent;
use crate::usage::UsageMode;
use crate::usage::UsageRecordResult;
use crate::usage::UsageRollup;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::extract::rejection::QueryRejection;
use axum::http::HeaderMap;
use axum::response::Json;
use serde::Deserialize;
use std::sync::Arc;
use utoipa::IntoParams;
use utoipa::ToSchema;

/// Query parameters for consumer usage reads.
#[derive(Deserialize, ToSchema, IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
pub(crate) struct ConsumerUsageQuery {
    /// Tenant id whose usage and allowance should be read.
    #[schema(example = "tenant-a")]
    #[param(example = "tenant-a")]
    tenant_id: String,
    /// Optional vault id for a per-vault usage scope.
    #[schema(example = "vault-a")]
    #[param(example = "vault-a")]
    vault_id: Option<String>,
}

/// Optional selector for a tenant usage rollup.
#[derive(Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct UsageRollupQuery {
    /// Vault id to read a per-vault rollup. Omit for the tenant-wide rollup.
    #[schema(example = "vault-a")]
    #[param(example = "vault-a")]
    vault_id: Option<String>,
}

/// Reads consumer usage, allowance balance, and explicit warning state.
#[utoipa::path(
    get,
    path = "/v1/consumer/usage",
    params(ConsumerUsageQuery),
    responses(
        (
            status = 200,
            description = "Consumer usage and allowance state for the selected tenant or tenant/vault scope.",
            body = ConsumerUsageState,
            content_type = "application/json"
        ),
        (
            status = 400,
            description = "Invalid tenant or vault identifier.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid bearer credentials.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Consumer usage read failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
pub(crate) async fn get_consumer_usage(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<ConsumerUsageQuery>, QueryRejection>,
) -> Result<Json<ConsumerUsageState>, ApiError> {
    check_api_auth(&headers, &server)?;
    let params = query_params(query)?;
    let usage = server
        .usage_ledger
        .consumer_usage(
            &params.tenant_id,
            params.vault_id.as_deref(),
            server.config.runtime_usage_mode(),
        )
        .inspect_err(|error| tracing::error!(error = %error, "consumer usage read failed"))
        .map_err(usage_error)?;
    Ok(Json(usage))
}

/// Reads consumer usage details including agent, model, and service breakdowns.
#[utoipa::path(
    get,
    path = "/v1/consumer/usage/details",
    params(ConsumerUsageQuery),
    responses(
        (
            status = 200,
            description = "Detailed consumer usage and allowance state for the selected tenant or tenant/vault scope.",
            body = ConsumerUsageDetails,
            content_type = "application/json"
        ),
        (
            status = 400,
            description = "Invalid tenant or vault identifier.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid bearer credentials.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Consumer usage details read failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
pub(crate) async fn get_consumer_usage_details(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<ConsumerUsageQuery>, QueryRejection>,
) -> Result<Json<ConsumerUsageDetails>, ApiError> {
    check_api_auth(&headers, &server)?;
    let params = query_params(query)?;
    let details = server
        .usage_ledger
        .consumer_usage_details(
            &params.tenant_id,
            params.vault_id.as_deref(),
            server.config.runtime_usage_mode(),
        )
        .inspect_err(|error| tracing::error!(error = %error, "consumer usage details read failed"))
        .map_err(usage_error)?;
    Ok(Json(details))
}

/// Credits a tenant allowance without integrating a payment processor.
#[utoipa::path(
    post,
    path = "/v1/consumer/top-up",
    request_body(
        content = ConsumerTopUpRequest,
        content_type = "application/json",
        example = json!({
            "tenantId": "tenant-a",
            "idempotencyKey": "top-up-2026-06-29-0001",
            "creditUnits": 100.0
        })
    ),
    responses(
        (
            status = 200,
            description = "Top-up accepted or replayed by idempotency key.",
            body = ConsumerTopUpState,
            content_type = "application/json"
        ),
        (
            status = 400,
            description = "Invalid top-up payload.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 409,
            description = "Idempotency key was replayed with a different top-up payload.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid bearer credentials.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Top-up persistence failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
pub(crate) async fn top_up_consumer(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    request: Result<Json<ConsumerTopUpRequest>, JsonRejection>,
) -> Result<Json<ConsumerTopUpState>, ApiError> {
    check_api_auth(&headers, &server)?;
    let request = json_payload(request)?;
    let state = server
        .usage_ledger
        .top_up(request, server.config.runtime_usage_mode())
        .map_err(|error| {
            if matches!(error, UsageError::IdempotencyConflict { .. }) {
                tracing::warn!("consumer top-up idempotency conflict");
            } else {
                tracing::error!(error = %error, "consumer top-up failed");
            }
            usage_error(error)
        })?;
    Ok(Json(state))
}

/// Records one tenant usage event and returns the resulting debit decision.
#[utoipa::path(
    post,
    path = "/v1/usage/events",
    request_body(
        content = UsageEvent,
        content_type = "application/json",
        example = json!({
            "tenantId": "tenant-a",
            "vaultId": "vault-a",
            "idempotencyKey": "usage-2026-06-29T00:00:00Z-0001",
            "source": "oneiron_cloud",
            "eventType": "inference",
            "agentId": "agent-a",
            "model": "model-a",
            "service": "inference",
            "tokenCounts": {
                "inputTokens": 1000,
                "outputTokens": 500,
                "cacheReadTokens": 2000,
                "cacheWriteTokens": 1000
            },
            "costRates": {
                "inputTokenUsdPerMillion": 2.0,
                "outputTokenUsdPerMillion": 4.0,
                "cacheReadTokenUsdPerMillion": 0.5,
                "cacheWriteTokenUsdPerMillion": 1.0
            },
            "serviceCostUsd": 0.044
        })
    ),
    responses(
        (
            status = 200,
            description = "Usage event accepted. Local and BYO sources return no debit; Oneiron Cloud mode records each idempotency key once.",
            body = UsageRecordResult,
            content_type = "application/json"
        ),
        (
            status = 400,
            description = "Invalid usage payload.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid bearer credentials.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Usage ledger persistence failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
pub(crate) async fn record_usage_event(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Json(event): Json<UsageEvent>,
) -> Result<Json<UsageRecordResult>, ApiError> {
    check_api_auth(&headers, &server)?;
    let usage_mode = usage_mode_for_event(&server.config, &event)?;
    let result = server
        .usage_ledger
        .record_event(event, usage_mode)
        .inspect_err(|error| tracing::error!(error = %error, "usage event record failed"))
        .map_err(usage_error)?;
    Ok(Json(result))
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

/// Reads a tenant-wide or tenant/vault-specific usage rollup.
#[utoipa::path(
    get,
    path = "/v1/usage/tenants/{tenant_id}/rollup",
    params(
        (
            "tenant_id" = String,
            Path,
            description = "Tenant id whose usage rollup should be read.",
            example = "tenant-a"
        ),
        UsageRollupQuery
    ),
    responses(
        (
            status = 200,
            description = "Tenant or vault usage rollup.",
            body = UsageRollup,
            content_type = "application/json"
        ),
        (
            status = 400,
            description = "Invalid tenant or vault identifier.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Missing or invalid bearer credentials.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 404,
            description = "No usage rollup exists for the selected tenant or vault.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Usage rollup read failed.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
pub(crate) async fn get_usage_rollup(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Path(tenant_id): Path<String>,
    query: Result<Query<UsageRollupQuery>, QueryRejection>,
) -> Result<Json<UsageRollup>, ApiError> {
    check_api_auth(&headers, &server)?;
    let params = query_params(query)?;
    let rollup = if let Some(vault_id) = params.vault_id {
        server
            .usage_ledger
            .vault_rollup(&tenant_id, &vault_id)
            .inspect_err(|error| tracing::error!(error = %error, "usage vault rollup read failed"))
            .map_err(usage_error)?
    } else {
        server
            .usage_ledger
            .tenant_rollup(&tenant_id)
            .inspect_err(|error| tracing::error!(error = %error, "usage tenant rollup read failed"))
            .map_err(usage_error)?
    };

    rollup
        .map(Json)
        .ok_or_else(|| ApiError::not_found("usage rollup", Some(&tenant_id)))
}

pub(crate) fn usage_error(error: UsageError) -> ApiError {
    if let UsageError::IdempotencyConflict {
        idempotency_key, ..
    } = &error
    {
        return consumer_top_up_idempotency_conflict_error(idempotency_key);
    }

    if let Some(field) = error.field() {
        return ApiError::bad_request(error.to_string(), Some(field));
    }

    ApiError::internal_server_error("usage ledger persistence failed")
}

pub(crate) fn consumer_top_up_idempotency_conflict_error(idempotency_key: &str) -> ApiError {
    ApiError::new(
        "idempotency key was replayed with a different request",
        ApiErrorDetails::IdempotencyReplayConflict {
            idempotency_key: Some(idempotency_key.to_owned()),
        },
        ["Reuse the original top-up request body or send a new JSON idempotencyKey."],
    )
}
