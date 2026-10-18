//! `/v1/owner/federation/connect`: the owner's Connect (ARCH-0043
//! #relationship-lifecycle, FIX 323), behind the same owner door as every
//! other owner route. Each host signs its half with its root key; the owner
//! carries the halves between the two hosts.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::{get, post};

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::federation_connect::{
    self, AcceptConnect, Accepted, ConnectGrant, ConnectIdentity, MintConnectGrant, Offer,
    OfferConnect,
};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/federation/connect", get(identity))
        .route("/federation/connect/grants", post(mint_grant))
        .route("/federation/connect/offer", post(offer))
        .route("/federation/connect/accept", post(accept))
}

/// `GET /v1/owner/federation/connect`: this vault's id and host key, what a
/// peer's owner names to offer it a pact.
async fn identity(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<ConnectIdentity> {
    owner(&auth, &server)?;
    let identity = blocking(move || federation_connect::identity(&server)).await?;
    Ok(Json(identity))
}

/// `POST /v1/owner/federation/connect/grants`: mints the guest grant a
/// Connect with a peer vault governs (FIX 3016), which the owner then names
/// in the offer or accept. Inert until the pact is Active.
async fn mint_grant(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<MintConnectGrant>, JsonRejection>,
) -> OwnerReply<ConnectGrant> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let minted =
        blocking(move || federation_connect::mint_grant(&server, &owner, &request)).await?;
    Ok(Json(minted))
}

/// `POST /v1/owner/federation/connect/offer`: this host's signed half of a
/// new pact with a peer vault, for the owner to carry to the peer.
async fn offer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<OfferConnect>, JsonRejection>,
) -> OwnerReply<Offer> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let offer = blocking(move || federation_connect::offer(&server, &owner, &request)).await?;
    Ok(Json(offer))
}

/// `POST /v1/owner/federation/connect/accept`: logs the Connect the peer's
/// half signs and answers this host's half of the same pact.
async fn accept(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<AcceptConnect>, JsonRejection>,
) -> OwnerReply<Accepted> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let accepted = blocking(move || federation_connect::accept(&server, &owner, &request)).await?;
    Ok(Json(accepted))
}
