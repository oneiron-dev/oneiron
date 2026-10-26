//! `/v1/owner/cloud-registration`: the owner links this vault to the Oneiron
//! cloud account and manages that link (G7, L13 seam 08:3x), through the
//! vault's one client (`crate::cloud_registration`), as `oneiron account`
//! does on a stopped vault. Each route takes a fresh owner proof first; a
//! login's poll names its flow by the opaque local handle its start
//! answered, in the body, never a code or a token. The owner is shown the
//! verification URI and the user code apart, and approves where the cloud
//! asks; no screen here.
//!
//! `POST .../start` (`{"replace": bool}`) starts a login; `POST .../poll`
//! (`{"flow": handle}`) sends at most one due poll; `GET .../status` reads
//! where the link stands and never refreshes it; `POST .../refresh` refreshes
//! it once; `POST .../logout` (`{"erase": bool}`) stops it, or erases every
//! token kept for it, then tries the revoke.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::{get, post};
use serde::Deserialize;

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::cloud_registration::{LoggedOut, Polled, Started, Status};
use crate::owner::OwnerResult;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/cloud-registration/start", post(start))
        .route("/cloud-registration/poll", post(poll))
        .route("/cloud-registration/status", get(status))
        .route("/cloud-registration/refresh", post(refresh))
        .route("/cloud-registration/logout", post(logout))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartLogin {
    /// Let the link replace a current link to another cloud account.
    #[serde(default)]
    replace: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PollLogin {
    /// The handle `start` answered.
    flow: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Logout {
    /// Erase every token kept for the link before the revoke.
    #[serde(default)]
    erase: bool,
}

async fn start(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<StartLogin>, JsonRejection>,
) -> OwnerReply<Started> {
    let owner = owner(&auth, &server)?;
    let body = json_payload(payload)?;
    let reply = blocking(move || -> OwnerResult<Started> {
        Ok(server
            .cloud_registration
            .start(server.vault(), &owner, body.replace)?)
    })
    .await?;
    Ok(Json(reply))
}

async fn poll(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<PollLogin>, JsonRejection>,
) -> OwnerReply<Polled> {
    let owner = owner(&auth, &server)?;
    let body = json_payload(payload)?;
    let reply = blocking(move || -> OwnerResult<Polled> {
        Ok(server
            .cloud_registration
            .poll(server.vault(), &owner, &body.flow)?)
    })
    .await?;
    Ok(Json(reply))
}

async fn status(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Status> {
    let owner = owner(&auth, &server)?;
    let reply = blocking(move || -> OwnerResult<Status> {
        Ok(server.cloud_registration.status(server.vault(), &owner)?)
    })
    .await?;
    Ok(Json(reply))
}

async fn refresh(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Status> {
    let owner = owner(&auth, &server)?;
    let reply = blocking(move || -> OwnerResult<Status> {
        Ok(server.cloud_registration.refresh(server.vault(), &owner)?)
    })
    .await?;
    Ok(Json(reply))
}

async fn logout(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<Logout>, JsonRejection>,
) -> OwnerReply<LoggedOut> {
    let owner = owner(&auth, &server)?;
    let body = json_payload(payload)?;
    let reply = blocking(move || -> OwnerResult<LoggedOut> {
        Ok(server
            .cloud_registration
            .logout(server.vault(), &owner, body.erase)?)
    })
    .await?;
    Ok(Json(reply))
}
