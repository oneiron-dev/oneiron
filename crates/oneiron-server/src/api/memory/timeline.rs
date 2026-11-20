//! The memory timeline route: `GET /v1/core/memory/{id}/timeline`, through
//! its verb-hook boundary (FIX 1435). `core_memory_timeline` is its call
//! surface and `core_memory_timeline_response` its projection; the parent
//! module keeps its DTOs.

use super::{
    CoreMemoryChange, CoreMemoryTimelineRecord, CoreMemoryTimelineRecordState,
    CoreMemoryTimelineResponse,
};
use crate::api::native_read_hooks::{
    NativeReadAnswer, NativeReadBody, NativeReadError, decoded, encoded, native_read_hooked,
};
use crate::api::{
    FacadeCall, MemoryTimelineQuery, core_engine_error, core_hydrate_deletion_metadata,
    parse_entity_id_param, query_params, read_filter_param, scoped_read_for_core_auth,
};
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorEnvelope;
use crate::projection;
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

/// Projects one timeline, its bodies, pinned changes included, decoded under
/// one budget of `body_bytes` (`[limits].projection_body_bytes`).
pub(crate) fn core_memory_timeline_response(
    read: &oneiron::claim::ScopedRead<'_>,
    result: oneiron::claim::ScopedReadResult<oneiron::MemoryTimeline>,
    view: View,
    body_bytes: usize,
) -> Result<CoreMemoryTimelineResponse, ApiError> {
    let mut bodies = projection::BodyBudget::new(read.vault(), body_bytes);
    let timeline = result.value;
    let mut narrowing = result.receipt;
    let projected = read
        .memory_timeline_parts_with_receipt(&timeline.records, Some(&narrowing.applied.as_filter()))
        .map_err(|error| core_engine_error("core memory timeline projection failed", error))?;
    narrowing.restrict_with(&projected.receipt);
    let mut parts: std::collections::BTreeMap<_, _> = timeline
        .records
        .iter()
        .map(|record| record.id)
        .zip(projected.value)
        .filter_map(|(id, body)| body.map(|body| (id, body)))
        .collect();
    let mut records = Vec::with_capacity(timeline.records.len());
    let deleted_anchor_visible = timeline.records.iter().any(|record| {
        record.id == timeline.anchor
            && record.state == oneiron::MemoryTimelineRecordState::Deleted
            && !narrowing.applied.deny_all
            && record.entity_type.is_some_and(|kind| {
                narrowing
                    .applied
                    .entity_types
                    .as_ref()
                    .is_none_or(|types| types.contains(&kind))
            })
    });
    if !parts.contains_key(&timeline.anchor) && !deleted_anchor_visible {
        narrowing.add_suppressed(parts.len());
        return Ok(CoreMemoryTimelineResponse {
            narrowing,
            anchor_id: timeline.anchor.to_hex(),
            records,
        });
    }
    for record in timeline.records {
        let item = if record.state == oneiron::MemoryTimelineRecordState::Deleted {
            if narrowing.applied.deny_all
                || record.entity_type.is_none_or(|kind| {
                    narrowing
                        .applied
                        .entity_types
                        .as_ref()
                        .is_some_and(|types| !types.contains(&kind))
                })
            {
                narrowing.add_suppressed(1);
                continue;
            }
            None
        } else {
            let Some((kind, learned_at, body)) = parts.remove(&record.id) else {
                continue;
            };
            if record.entity_type != Some(kind)
                || record.learned_at != Some(learned_at)
                || record.body_bytes != Some(body.len())
            {
                narrowing.add_suppressed(1);
                continue;
            }
            Some(bodies.project(&record.id, kind, learned_at, &body, view))
        };
        records.push(CoreMemoryTimelineRecord {
            id: record.id.to_hex(),
            state: core_memory_timeline_state(record.state),
            entity_type: record.entity_type,
            occurred_start: record.occurred_start,
            occurred_end: record.occurred_end,
            learned_at: record.learned_at,
            body_bytes: record.body_bytes,
            deletion: record.deletion.map(core_hydrate_deletion_metadata),
            supersedes: record
                .supersedes
                .into_iter()
                .map(|id| id.to_hex())
                .collect(),
            superseded_by: record
                .superseded_by
                .into_iter()
                .map(|id| id.to_hex())
                .collect(),
            item,
            changes: Vec::new(),
        });
    }
    let content_visible: std::collections::BTreeSet<_> = records
        .iter()
        .filter(|record| record.item.is_some())
        .map(|record| record.id.clone())
        .collect();
    for record in &mut records {
        if !content_visible.contains(&record.id) {
            continue;
        }
        let after_id = oneiron::EntityId::from_hex(&record.id)
            .map_err(|_| ApiError::internal_server_error("timeline successor id"))?;
        for before_id in &record.supersedes {
            if !content_visible.contains(before_id) {
                continue;
            }
            let old_id = oneiron::EntityId::from_hex(before_id)
                .map_err(|_| ApiError::internal_server_error("timeline predecessor id"))?;
            let pinned = read
                .memory_supersession_parts_with_receipt(
                    &old_id,
                    &after_id,
                    Some(&narrowing.applied.as_filter()),
                )
                .map_err(|error| core_engine_error("core memory pinned change failed", error))?;
            narrowing.restrict_with(&pinned.receipt);
            let Some((
                (before_kind, before_at, before_body, before_revision),
                (after_kind, after_at, after_body, after_revision),
            )) = pinned.value
            else {
                continue;
            };
            record.changes.push(CoreMemoryChange {
                before_id: before_id.clone(),
                after_id: record.id.clone(),
                before: bodies.project_at(
                    &old_id,
                    before_kind,
                    before_at,
                    &before_body,
                    view,
                    oneiron::memory::ReadMode::Pinned(before_revision),
                ),
                after: bodies.project_at(
                    &after_id,
                    after_kind,
                    after_at,
                    &after_body,
                    view,
                    oneiron::memory::ReadMode::Pinned(after_revision),
                ),
            });
        }
    }
    let visible: std::collections::BTreeSet<_> =
        records.iter().map(|record| record.id.clone()).collect();
    for record in &mut records {
        record.supersedes.retain(|id| visible.contains(id));
        record.superseded_by.retain(|id| visible.contains(id));
    }
    Ok(CoreMemoryTimelineResponse {
        narrowing,
        anchor_id: timeline.anchor.to_hex(),
        records,
    })
}

pub(crate) fn core_memory_timeline_state(
    state: oneiron::MemoryTimelineRecordState,
) -> CoreMemoryTimelineRecordState {
    match state {
        oneiron::MemoryTimelineRecordState::Live => CoreMemoryTimelineRecordState::Live,
        oneiron::MemoryTimelineRecordState::Superseded => CoreMemoryTimelineRecordState::Superseded,
        oneiron::MemoryTimelineRecordState::Retracted => CoreMemoryTimelineRecordState::Retracted,
        oneiron::MemoryTimelineRecordState::Deleted => CoreMemoryTimelineRecordState::Deleted,
        oneiron::MemoryTimelineRecordState::Missing => CoreMemoryTimelineRecordState::Missing,
    }
}
