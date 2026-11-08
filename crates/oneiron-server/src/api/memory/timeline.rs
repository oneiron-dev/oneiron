//! The memory timeline route: `GET /v1/core/memory/{id}/timeline`, through
//! its verb-hook boundary (FIX 1435). `core_memory_timeline` is its call
//! surface; the parent module keeps its DTOs and
//! `core_memory_timeline_response`.

use super::{CoreMemoryTimelineResponse, core_memory_timeline_response};
use crate::api::native_read_hooks::{
    NativeReadAnswer, NativeReadBody, NativeReadError, decoded, encoded, native_read_hooked,
};
use crate::api::{
    FacadeCall, MemoryTimelineQuery, core_engine_error, parse_entity_id_param, query_params,
    read_filter_param, scoped_read_for_core_auth,
};
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorEnvelope;
use crate::projection::View;
use crate::server::SyncServer;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::extract::rejection::QueryRejection;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use oneiron::EntityId;
use oneiron::code_run::vault_read::VaultReadMethod;
use serde::Deserialize;
use serde_json::Value;
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
        MemoryTimelineQuery
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
    headers: HeaderMap,
    extensions: Extensions,
    Path(id_hex): Path<String>,
    query: Result<Query<MemoryTimelineQuery>, QueryRejection>,
) -> Result<Json<Value>, NativeReadError> {
    auth.require(CoreScope::Read)?;
    let id = parse_entity_id_param(&id_hex, "id")?;
    let params = query_params(query)?;
    // The native request the route's path and query name (FIX 1435).
    let mut request = serde_json::json!({ "id": id.to_hex() });
    if let Some(view) = params.view {
        request["view"] = Value::from(view.as_str());
    }
    // The caller's filter, the URL-encoded JSON the query names (FIX 3977).
    if let Some(filter) = read_filter_param(params.filter.as_deref())? {
        request["filter"] = encoded(&filter)?;
    }
    let call = FacadeCall::http(&server, &auth, &headers, &extensions);
    let answer = core_memory_timeline_hooked(&server, &call, request).await?;
    Ok(Json(answer.value))
}

/// `GET /v1/core/memory/{id}/timeline` on its native `request`, for
/// `call`'s caller, through its verb-hook boundary as
/// `memory.memory_timeline` (FIX 1435). The anchor is parsed and the
/// caller's read admitted first; the pre chain then runs before any row is
/// read. The read runs on the anchor and view the chain left.
pub(crate) async fn core_memory_timeline_hooked(
    server: &Arc<SyncServer>,
    call: &FacadeCall<'_>,
    request: Value,
) -> Result<NativeReadAnswer, NativeReadError> {
    let auth = call.auth();
    let admitted = admit_memory_timeline(&request)?;
    let scoped_read = scoped_read_for_core_auth(&server.vault, auth)?;
    let request = NativeReadBody::split(request, &[]);
    native_read_hooked(
        server,
        call,
        VaultReadMethod::MemoryTimeline,
        request,
        admitted,
        admit_memory_timeline,
        |(id, view, filter)| read_memory_timeline(server, scoped_read, id, view, filter),
    )
    .await
}

/// The timeline route's request: the native timeline request that its path
/// and query name.
#[derive(Deserialize)]
struct MemoryTimelineRequest {
    id: String,
    #[serde(default)]
    view: Option<View>,
    /// The caller's retrieval filter (FIX 3977): it only narrows.
    #[serde(default)]
    filter: Option<oneiron::memory::ReadFilterInput>,
}

/// The route's own admission of the timeline `request`: its anchor, the
/// view its records are projected in, and the caller's filter.
fn admit_memory_timeline(
    request: &Value,
) -> Result<(EntityId, View, Option<oneiron::memory::ReadFilterInput>), ApiError> {
    let request: MemoryTimelineRequest = decoded(request)?;
    let id = parse_entity_id_param(&request.id, "id")?;
    Ok((id, request.view.unwrap_or(View::Summary), request.filter))
}

/// The timeline of `id`, read on `scoped_read` narrowed by the caller's
/// `filter` and projected in `view`. The answer goes beside the rows the final
/// response lists it was derived from
/// ([`CoreMemoryTimelineResponse::producer_rows`], FIX 1435).
async fn read_memory_timeline(
    server: &SyncServer,
    scoped_read: oneiron::claim::ScopedRead<'_>,
    id: EntityId,
    view: View,
    filter: Option<oneiron::memory::ReadFilterInput>,
) -> Result<NativeReadAnswer, NativeReadError> {
    let request = filter
        .as_ref()
        .map(oneiron::memory::ReadFilterInput::to_filter);
    let scoped_read = scoped_read.with_read_filter(request.as_ref());
    let timeline = scoped_read.memory_timeline(&id).map_err(|error| {
        tracing::error!(kind = ?error.kind(), id = %id.to_hex(), "core memory timeline failed");
        core_engine_error("core memory timeline failed", error)
    })?;

    if timeline.records.is_empty()
        || (timeline.records.len() == 1
            && timeline.records[0].state == oneiron::MemoryTimelineRecordState::Missing)
    {
        return Err(NativeReadError::with_read_receipt(
            ApiError::not_found("entity", Some(&id.to_hex())),
            timeline.receipt,
        ));
    }

    let response = core_memory_timeline_response(
        &scoped_read,
        timeline,
        view,
        server.config.limits.projection_body_bytes,
    )?;
    if response.records.is_empty() {
        return Err(NativeReadError::with_read_receipt(
            ApiError::not_found("entity", Some(&id.to_hex())),
            response.narrowing,
        ));
    }
    let rows = response.producer_rows();
    let value = encoded(&response)?;
    Ok(match rows {
        Some(rows) => NativeReadAnswer::listed(value, rows),
        None => NativeReadAnswer::unlisted(value),
    })
}

impl CoreMemoryTimelineResponse {
    /// The rows this timeline answer was derived from, as its route lists
    /// them for the release of a drained retry (FIX 1435): its anchor, every
    /// record it returns, deleted shells among them, and both ends of every
    /// change it returns. `None` when one of those ids does not parse.
    fn producer_rows(&self) -> Option<Vec<EntityId>> {
        let changes = self.records.iter().flat_map(|record| &record.changes);
        let mut rows = std::iter::once(&self.anchor_id)
            .chain(self.records.iter().map(|record| &record.id))
            .chain(changes.flat_map(|change| [&change.before_id, &change.after_id]))
            .map(|id| EntityId::from_hex(id).ok())
            .collect::<Option<Vec<_>>>()?;
        rows.sort_unstable();
        rows.dedup();
        Some(rows)
    }
}
