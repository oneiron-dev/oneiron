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

use axum::extract::State;
use axum::response::Json;
use axum::routing::{get, post};
use serde::Deserialize;

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::cloud_registration::{LoggedOut, Polled, Started, Status};
use crate::owner::OwnerResult;
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "post",
                path: "/cloud-registration/start",
                summary: "Start a login that links this vault to the owner's Oneiron cloud account (G7); `replace` (bool) lets the link replace a current link to another cloud account. A pending start answers `flow`, the opaque local handle a poll names, and the `verification_uri` and `user_code` apart: the owner approves where the cloud asks.",
                row: None,
                shape: None,
            },
            post(start),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/cloud-registration/poll",
                summary: "Send at most one due poll of the login `flow` names (the handle `start` answered, never a code or a token): still pending, with when to poll next, or linked, with the link's first status and any link it replaced.",
                row: None,
                shape: None,
            },
            post(poll),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/cloud-registration/status",
                summary: "Where the vault's cloud account link stands, read without refreshing it: not configured, signed out, erasing, registered, needing a refresh or a login, unavailable or failed.",
                row: None,
                shape: None,
            },
            get(status),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/cloud-registration/refresh",
                summary: "Refresh the vault's cloud account link once; answers where the link then stands.",
                row: None,
                shape: None,
            },
            post(refresh),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/cloud-registration/logout",
                summary: "Stop the vault's cloud account link, or with `erase` (bool) erase every token kept for it first, then try the revoke.",
                row: None,
                shape: None,
            },
            post(logout),
        ),
    ]
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
    payload: OwnerJsonBody<StartLogin>,
) -> OwnerReply<Started> {
    let owner = owner(&auth, &server)?;
    let body = payload.read(&server).await?;
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
    payload: OwnerJsonBody<PollLogin>,
) -> OwnerReply<Polled> {
    let owner = owner(&auth, &server)?;
    let body = payload.read(&server).await?;
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
    payload: OwnerJsonBody<Logout>,
) -> OwnerReply<LoggedOut> {
    let owner = owner(&auth, &server)?;
    let body = payload.read(&server).await?;
    let reply = blocking(move || -> OwnerResult<LoggedOut> {
        Ok(server
            .cloud_registration
            .logout(server.vault(), &owner, body.erase)?)
    })
    .await?;
    Ok(Json(reply))
}
