use super::*;

#[utoipa::path(
    get,
    path = "/v1/core/memory/{id}/watch",
    params(("id" = String, Path, description = "Hex claim id to watch.")),
    responses(
        (status = 200, description = "Read the owner's durable per-entry watch flag.", body = CoreMemoryWatchResponse),
        (status = 400, description = "Invalid id or SAVED_QUERY kind not registered.", body = ApiErrorEnvelope),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope),
        (status = 403, description = "Human owner binding or required scope absent.", body = ApiErrorEnvelope),
        (status = 404, description = "Claim not found or not readable.", body = ApiErrorEnvelope)
    )
)]
pub(in crate::api) async fn core_memory_watch_read(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(id_hex): Path<String>,
) -> Result<Json<CoreMemoryWatchResponse>, super::facade::FacadeApiError> {
    let (owner, anchor) = watch_identity(&auth, &server, &id_hex, CoreScope::Read, false)?;
    let watch = oneiron::saved_query::memory_watch(&server.vault, owner, anchor)
        .map_err(|error| core_engine_error("memory watch read failed", error))?;
    Ok(Json(CoreMemoryWatchResponse {
        watched: watch.is_some(),
        query_ref: watch.map(|watch| watch.query_ref.to_hex()),
    }))
}

#[utoipa::path(
    put,
    path = "/v1/core/memory/{id}/watch",
    params(("id" = String, Path, description = "Hex claim id to watch.")),
    responses(
        (status = 200, description = "Enable the owner's durable per-entry watch flag.", body = CoreMemoryWatchResponse),
        (status = 400, description = "Invalid id or SAVED_QUERY kind not registered.", body = ApiErrorEnvelope),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope),
        (status = 403, description = "Human owner binding or required scope absent.", body = ApiErrorEnvelope),
        (status = 404, description = "Claim not found or not readable.", body = ApiErrorEnvelope)
    )
)]
pub(in crate::api) async fn core_memory_watch_enable(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(id_hex): Path<String>,
) -> Result<Json<CoreMemoryWatchResponse>, super::facade::FacadeApiError> {
    set_core_memory_watch(auth, server, id_hex, true)
}

#[utoipa::path(
    delete,
    path = "/v1/core/memory/{id}/watch",
    params(("id" = String, Path, description = "Hex claim id to watch.")),
    responses(
        (status = 200, description = "Disable the owner's durable per-entry watch flag.", body = CoreMemoryWatchResponse),
        (status = 400, description = "Invalid id or SAVED_QUERY kind not registered.", body = ApiErrorEnvelope),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope),
        (status = 403, description = "Human owner binding or required scope absent.", body = ApiErrorEnvelope),
        (status = 404, description = "Claim not found or not readable.", body = ApiErrorEnvelope)
    )
)]
pub(in crate::api) async fn core_memory_watch_disable(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(id_hex): Path<String>,
) -> Result<Json<CoreMemoryWatchResponse>, super::facade::FacadeApiError> {
    set_core_memory_watch(auth, server, id_hex, false)
}

fn set_core_memory_watch(
    auth: CoreAuth,
    server: Arc<SyncServer>,
    id_hex: String,
    enabled: bool,
) -> Result<Json<CoreMemoryWatchResponse>, super::facade::FacadeApiError> {
    let (owner, anchor) = watch_identity(&auth, &server, &id_hex, CoreScope::Write, enabled)?;
    let watch = oneiron::saved_query::set_memory_watch(
        &server.vault,
        owner,
        anchor,
        enabled,
        unix_seconds_now(),
    )?;
    Ok(Json(CoreMemoryWatchResponse {
        watched: watch.is_some(),
        query_ref: watch.map(|watch| watch.query_ref.to_hex()),
    }))
}

fn watch_identity(
    auth: &CoreAuth,
    server: &SyncServer,
    id_hex: &str,
    scope: CoreScope,
    require_visible: bool,
) -> Result<(oneiron::EntityId, oneiron::EntityId), super::facade::FacadeApiError> {
    auth.require(scope)?;
    auth.require_unrestricted_record_scope()?;
    if !auth.is_owner_grade() || auth.actor_class() != Some("human") {
        return Err(ApiError::forbidden_scope("owner+human").into());
    }
    let principal = auth.require_registered_principal()?;
    let owner = parse_entity_id_param(principal, "principal_ref")?;
    server
        .vault
        .memory(owner, oneiron::EdgeActorClass::Human)
        .verify_owner()?;
    let anchor = parse_entity_id_param(id_hex, "id")?;
    if !require_visible {
        return Ok((owner, anchor));
    }
    let read = scoped_read_for_core_auth(&server.vault, auth)?;
    let result = read
        .memory_timeline(&anchor)
        .map_err(|error| core_engine_error("memory watch visibility failed", error))?;
    if !result.value.records.iter().any(|record| {
        record.id == anchor && record.entity_type == Some(oneiron::registry::ENTITY_TYPE_CLAIM)
    }) {
        return Err(ApiError::not_found("claim", Some(id_hex)).into());
    }
    Ok((owner, anchor))
}
