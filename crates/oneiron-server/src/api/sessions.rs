//! Minimal session mode and ephemeral presence routes.
use super::{conversation_members::actor, core_engine_error, json_payload, parse_entity_id_param};
use crate::{
    auth::{CoreAuth, CoreScope},
    error::{ApiError, EnvelopedApiError},
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
    server
        .vault
        .set_session_mode_within(id, req.mode, facet_ref, actor(&auth, req.actor)?, &facets)
        .map_err(|e| core_engine_error("session mode failed", e))?;
    Ok(Json(
        json!({"mode":req.mode,"facet_ref":facet_ref.map(|facet| facet.to_hex())}),
    ))
}
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
