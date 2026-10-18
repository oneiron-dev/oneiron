//! `/v1/owner/worlds/privacy`: a holder answers the world-privacy requests
//! agents raised (FIX 4480). He accepts or declines an agent's proposal of
//! stricter settings, confirms or declines a widen ask, and undoes an agent's
//! tighten from its notice. Each is his own act from whichever linked surface
//! he is on (`owner()`), written by the engine's one settings transaction:
//! a yes is `by: Owner` with `answer` = the request.
//!
//! `/v1/owner/worlds/privacy/widen-unanimity`: the vault's "widen needs every
//! owner" setting and its per-world overrides.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::policy_model::{
    WidenUnanimity, WorldPrivacyAnswer, WorldPrivacyReceipt, WorldPrivacyRequest,
};
use serde::Deserialize;

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::{OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/worlds/privacy/requests", get(list))
        .route("/worlds/privacy/proposals/accept", post(accept))
        .route("/worlds/privacy/proposals/decline", post(decline))
        .route("/worlds/privacy/asks/confirm", post(accept))
        .route("/worlds/privacy/asks/decline", post(decline))
        .route("/worlds/privacy/undo", post(undo))
        .route(
            "/worlds/privacy/widen-unanimity",
            get(unanimity).post(set_unanimity),
        )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestPage {
    /// Only the requests still waiting for a holder.
    #[serde(default)]
    pending: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnswerRequest {
    /// The request, 32 hex characters.
    request: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UndoChange {
    /// The settings receipt the notice carried.
    receipt: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetUnanimity {
    /// The world whose override this sets, 32 hex; none sets the vault's.
    #[serde(default)]
    world: Option<String>,
    /// On or off; none clears a world's override.
    #[serde(default)]
    on: Option<bool>,
}

/// `GET /v1/owner/worlds/privacy/requests[?pending=true]`: the requests,
/// newest first.
async fn list(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<RequestPage>, QueryRejection>,
) -> OwnerReply<Vec<WorldPrivacyRequest>> {
    owner(&auth, &server)?;
    let page = query_params(query)?;
    let requests = blocking(move || -> OwnerResult<Vec<WorldPrivacyRequest>> {
        Ok(server
            .vault()
            .world_privacy_requests(page.pending.unwrap_or(false))?)
    })
    .await?;
    Ok(Json(requests))
}

/// `POST /v1/owner/worlds/privacy/{proposals/accept,asks/confirm}`: the
/// holder's yes. It applies the frozen settings as his own act, or, under
/// "widen needs every owner", counts his yes until every owner's is in.
async fn accept(
    auth: CoreAuth,
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<AnswerRequest>, JsonRejection>,
) -> OwnerReply<WorldPrivacyAnswer> {
    answer(auth, headers, server, payload, true).await
}

/// `POST /v1/owner/worlds/privacy/{proposals/decline,asks/decline}`: the
/// holder declines the request, or cancels a proposal from its notice.
async fn decline(
    auth: CoreAuth,
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<AnswerRequest>, JsonRejection>,
) -> OwnerReply<WorldPrivacyAnswer> {
    answer(auth, headers, server, payload, false).await
}

async fn answer(
    auth: CoreAuth,
    headers: HeaderMap,
    server: Arc<SyncServer>,
    payload: Result<Json<AnswerRequest>, JsonRejection>,
    yes: bool,
) -> OwnerReply<WorldPrivacyAnswer> {
    let owner = owner(&auth, &server)?;
    let surface = super::machine_routes::act_surface(&server, &auth, &headers);
    let body = json_payload(payload)?;
    let answered = blocking(move || -> OwnerResult<WorldPrivacyAnswer> {
        let request = entity_id("request", &body.request)?;
        Ok(server
            .vault()
            .answer_world_privacy_request(&owner, surface, request, yes)?)
    })
    .await?;
    Ok(Json(answered))
}

/// `POST /v1/owner/worlds/privacy/undo`: the notice's one tap. It restores
/// the settings before an agent's tighten, as the holder's own act.
async fn undo(
    auth: CoreAuth,
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<UndoChange>, JsonRejection>,
) -> OwnerReply<WorldPrivacyReceipt> {
    let owner = owner(&auth, &server)?;
    let surface = super::machine_routes::act_surface(&server, &auth, &headers);
    let body = json_payload(payload)?;
    let receipt = blocking(move || -> OwnerResult<WorldPrivacyReceipt> {
        Ok(server
            .vault()
            .undo_world_privacy_change(&owner, surface, &body.receipt)?)
    })
    .await?;
    Ok(Json(receipt))
}

/// `GET /v1/owner/worlds/privacy/widen-unanimity`: the setting as it stands.
async fn unanimity(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<WidenUnanimity> {
    owner(&auth, &server)?;
    let row = blocking(move || -> OwnerResult<WidenUnanimity> {
        Ok(server.vault().widen_needs_every_owner()?)
    })
    .await?;
    Ok(Json(row))
}

/// `POST /v1/owner/worlds/privacy/widen-unanimity`: an owner sets the vault's
/// setting, or a world's override.
async fn set_unanimity(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SetUnanimity>, JsonRejection>,
) -> OwnerReply<WidenUnanimity> {
    let owner = owner(&auth, &server)?;
    let body = json_payload(payload)?;
    let row = blocking(move || -> OwnerResult<WidenUnanimity> {
        let world = body
            .world
            .as_deref()
            .map(|world| entity_id("world", world))
            .transpose()?;
        Ok(server
            .vault()
            .set_widen_needs_every_owner(&owner, world, body.on)?)
    })
    .await?;
    Ok(Json(row))
}
