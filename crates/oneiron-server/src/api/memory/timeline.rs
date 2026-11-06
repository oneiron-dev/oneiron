//! The memory timeline route: `GET /v1/core/memory/{id}/timeline`.
//! `core_memory_timeline` is its call surface; the parent module keeps its
//! DTOs and `core_memory_timeline_response`.

use super::{CoreMemoryTimelineResponse, core_memory_timeline_response};
use crate::api::{
    ViewQuery, core_engine_error, parse_entity_id_param, query_params, scoped_read_for_core_auth,
};
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::projection::View;
use crate::server::SyncServer;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::extract::rejection::QueryRejection;
use axum::response::Json;
use std::sync::Arc;

/// Return renderer-ready supersession timeline data for one memory record.
#[utoipa::path(
    get,
    path = "/v1/core/memory/{id}/timeline",
    params(
        (
            "id" = String,
            Path,
            description = "Hex entity id whose supersession chain should be rendered.",
            example = "0123456789abcdef0123456789abcdef"
        ),
        ViewQuery
    ),
    responses(
        (status = 200, description = "Stable ordered memory supersession timeline.", body = CoreMemoryTimelineResponse, content_type = "application/json"),
        (status = 400, description = "Malformed entity id or view.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Anchor entity was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Timeline lookup failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_memory_timeline(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(id_hex): Path<String>,
    query: Result<Query<ViewQuery>, QueryRejection>,
) -> Result<Json<CoreMemoryTimelineResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let id = parse_entity_id_param(&id_hex, "id")?;
    let params = query_params(query)?;
    let view = params.view.unwrap_or(View::Summary);
    let scoped_read = scoped_read_for_core_auth(&server.vault, &auth)?;
    let timeline = scoped_read.memory_timeline(&id).map_err(|error| {
        tracing::error!(kind = ?error.kind(), id = %id.to_hex(), "core memory timeline failed");
        core_engine_error("core memory timeline failed", error)
    })?;

    if timeline.records.is_empty()
        || (timeline.records.len() == 1
            && timeline.records[0].state == oneiron::MemoryTimelineRecordState::Missing)
    {
        return Err(
            EnvelopedApiError::from(ApiError::not_found("entity", Some(&id.to_hex())))
                .with_read_receipt(timeline.receipt),
        );
    }

    let response = core_memory_timeline_response(
        &scoped_read,
        timeline,
        view,
        server.config.limits.projection_body_bytes,
    )?;
    if response.records.is_empty() {
        return Err(
            EnvelopedApiError::from(ApiError::not_found("entity", Some(&id.to_hex())))
                .with_read_receipt(response.narrowing),
        );
    }
    Ok(Json(response))
}
