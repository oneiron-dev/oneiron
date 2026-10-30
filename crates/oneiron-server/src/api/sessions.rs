//! Minimal session mode and ephemeral presence routes.
use super::{conversation_members::actor, core_engine_error, json_payload, parse_entity_id_param};
use crate::{
    auth::{CoreAuth, CoreScope},
    error::{ApiError, ApiErrorEnvelope, EnvelopedApiError},
    server::SyncServer,
};
use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
};
use oneiron::federation::{ScopeAxis, ScopeId};
use oneiron::{EntityId, conversation::SessionMode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
#[derive(Deserialize)]
pub(super) struct ModeWrite {
    mode: SessionMode,
    /// The facet the session's writes land in, for a credential narrowed to
    /// facets that holds it (owner ruling FACET-READ). Omitted keeps the
    /// stored placement; `null` clears it.
    #[serde(default, deserialize_with = "present")]
    facet_ref: Option<Option<EntityId>>,
    #[serde(default)]
    actor: Option<EntityId>,
}
/// A field that is present, even as `null`; `#[serde(default)]` leaves an
/// omitted one `None`.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}
#[derive(Deserialize)]
pub(super) struct PresenceWrite {
    ids: Vec<EntityId>,
    #[serde(default)]
    actor: Option<EntityId>,
}
/// Set one session's mode and facet placement.
#[utoipa::path(
    patch,
    path = "/v1/core/sessions/{id}",
    params(("id" = String, Path, description = "Hex session id.")),
    request_body(content = Object, description = "`ModeWrite`: `mode` (`direct`, `group` or `council`), an optional `facet_ref` (32 hex, or null to clear; omitted keeps the stored placement) and an optional `actor` (32 hex).", content_type = "application/json"),
    responses(
        (status = 200, description = "The session's mode and facet placement.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed session id or request body.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:write or a lane record scope the session sits in.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Session was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 409, description = "The key's first request never settled an outcome (`idempotent_outcome_unknown`, FIX 9527): its effect may have landed, so it is not run again; read the resource's state, or send a new `Idempotency-Key` to act again. A retry whose first request counted committed writes gets `idempotent_reply_not_kept` instead (FIX 10379): those writes landed, and the reply was not kept.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Session mode write failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(super) async fn mode(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(session): Path<String>,
    payload: Result<Json<ModeWrite>, JsonRejection>,
) -> Result<Json<Value>, EnvelopedApiError> {
    // A credential narrowed to facets may set the mode of a session placed in
    // one of them, naming only a facet it reads (Engine Q2); any other
    // narrowing fails closed.
    auth.require_lane_record_scope()?;
    auth.require_granted(CoreScope::Write)?;
    let id = parse_entity_id_param(&session, "session_id")?;
    let req = json_payload(payload)?;
    let facets = auth
        .verified_slip()
        .map_or(ScopeAxis::All, |proof| proof.scope().facets.clone());
    if let Some(Some(facet)) = req.facet_ref
        && !facets.contains(&ScopeId(facet))
    {
        return Err(ApiError::forbidden_scope("record-scope").into());
    }
    // An omitted placement stays as stored. The write below still refuses a
    // narrowed writer a session placed outside its facets, as missing.
    let facet_ref = match req.facet_ref {
        Some(facet) => facet,
        None => server.vault.session_facet(id).ok().flatten(),
    };
    // A slip's own records, worlds and liveness bind the session in the
    // write itself (FIX 8218); its facets stay the ones named above.
    let actor = actor(&auth, req.actor)?;
    match auth.verified_slip() {
        Some(proof) => server
            .vault
            .set_session_mode_bound(id, req.mode, facet_ref, actor, &facets, proof),
        None => server
            .vault
            .set_session_mode_within(id, req.mode, facet_ref, actor, &facets),
    }
    .map_err(|e| core_engine_error("session mode failed", e))?;
    Ok(Json(
        json!({"mode":req.mode,"facet_ref":facet_ref.map(|facet| facet.to_hex())}),
    ))
}
/// Set who is present in one session.
#[utoipa::path(
    post,
    path = "/v1/core/sessions/{id}/presence",
    params(("id" = String, Path, description = "Hex session id.")),
    request_body(content = Object, description = "`PresenceWrite`: `ids` (32 hex each) and an optional `actor` (32 hex).", content_type = "application/json"),
    responses(
        (status = 200, description = "The session's presence in arrival order.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed session id or request body.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:write.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Session was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 409, description = "The key's first request never settled an outcome (`idempotent_outcome_unknown`, FIX 9527): its effect may have landed, so it is not run again; read the resource's state, or send a new `Idempotency-Key` to act again. A retry whose first request counted committed writes gets `idempotent_reply_not_kept` instead (FIX 10379): those writes landed, and the reply was not kept.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Session presence write failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(super) async fn presence(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(session): Path<String>,
    payload: Result<Json<PresenceWrite>, JsonRejection>,
) -> Result<Json<Value>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let id = parse_entity_id_param(&session, "session_id")?;
    let req = json_payload(payload)?;
    server
        .vault
        .set_presence(id, &req.ids, actor(&auth, req.actor)?)
        .map_err(|e| core_engine_error("session presence failed", e))?;
    // The stored arrival order, not the order this request named: a
    // participant who stays keeps its place and newcomers follow (OF-528).
    let presence = server
        .vault
        .session_presence(id)
        .map_err(|e| core_engine_error("session presence failed", e))?;
    Ok(Json(
        json!({"active_participant_ids":presence.active_participant_ids}),
    ))
}
