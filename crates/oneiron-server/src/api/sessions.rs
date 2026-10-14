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
use oneiron::federation::ScopeId;
use oneiron::{EntityId, conversation::SessionMode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
#[derive(Deserialize)]
pub(super) struct ModeWrite {
    mode: SessionMode,
    /// The facet the session's writes land in, for a credential narrowed to
    /// facets that holds it (owner ruling FACET-READ).
    #[serde(default)]
    facet_ref: Option<EntityId>,
    #[serde(default)]
    actor: Option<EntityId>,
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
    auth.require(CoreScope::Write)?;
    let id = parse_entity_id_param(&session, "session_id")?;
    let req = json_payload(payload)?;
    // A credential narrowed to facets names only one it reads (Engine Q2).
    if let (Some(facet), Some(proof)) = (req.facet_ref, auth.verified_slip())
        && !proof.scope().facets.contains(&ScopeId(facet))
    {
        return Err(ApiError::forbidden_scope("record-scope").into());
    }
    server
        .vault
        .set_session_mode(id, req.mode, req.facet_ref, actor(&auth, req.actor)?)
        .map_err(|e| core_engine_error("session mode failed", e))?;
    Ok(Json(
        json!({"mode":req.mode,"facet_ref":req.facet_ref.map(|facet| facet.to_hex())}),
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
    Ok(Json(json!({"active_participant_ids":req.ids})))
}
