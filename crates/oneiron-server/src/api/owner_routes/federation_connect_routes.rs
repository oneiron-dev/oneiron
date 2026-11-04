//! `/v1/owner/federation/connect`: the owner's Connect (ARCH-0043
//! #relationship-lifecycle, FIX 323), behind the same owner door as every
//! other owner route. Each host signs its half with its root key; the owner
//! carries the halves between the two hosts. Each route runs its
//! `vault.federation.connect.*` row's verb hooks once around the call, as
//! the owner in person (FIX 8201).

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::task_verb::sdk::{ConnectAccepted, ConnectGrant, EmptyRequest, Offer};
use serde_json::Value;

use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, hooked_owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::federation_connect::{self, AcceptConnect, MintConnectGrant, OfferConnect};
use crate::owner::hooked_row;
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/federation/connect",
                summary: "This vault's id and host key, what a peer's owner names to offer it a pact.",
                row: None,
                shape: None,
            },
            get(identity),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/federation/connect/grants",
                summary: "Mints the guest grant a Connect with a peer vault governs: named local worlds, read and propose only, inside the vault's Connect guest ceiling. Inert until the pact is Active.",
                row: None,
                shape: Some(RestShape::json(
                    mint_grant_body_schema,
                    connect_grant_schema,
                )),
            },
            post(mint_grant),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/federation/connect/offer",
                summary: "This host's signed half of a new pact with a peer vault, for the owner to carry to the peer.",
                row: None,
                shape: Some(RestShape::json(
                    offer_connect_body_schema,
                    connect_offer_schema,
                )),
            },
            post(offer),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/federation/connect/accept",
                summary: "Logs the Connect the peer's half signs and answers this host's half of the same pact.",
                row: None,
                shape: Some(RestShape::json(
                    accept_connect_body_schema,
                    connect_accepted_schema,
                )),
            },
            post(accept),
        ),
    ]
}

/// The OpenAPI schema of `POST /v1/owner/federation/connect/grants`'s body
/// (FIX 11611): [`MintConnectGrant`].
pub(crate) fn mint_grant_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<MintConnectGrant>()
}

/// The OpenAPI schema of `POST /v1/owner/federation/connect/grants`'s answer
/// (FIX 11611): [`ConnectGrant`].
pub(crate) fn connect_grant_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ConnectGrant>()
}

/// The OpenAPI schema of `POST /v1/owner/federation/connect/offer`'s body
/// (FIX 11611): [`OfferConnect`].
pub(crate) fn offer_connect_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<OfferConnect>()
}

/// The OpenAPI schema of `POST /v1/owner/federation/connect/offer`'s answer
/// (FIX 11611): this host's signed half, [`Offer`].
pub(crate) fn connect_offer_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<Offer>()
}

/// The OpenAPI schema of `POST /v1/owner/federation/connect/accept`'s body
/// (FIX 11611): [`AcceptConnect`].
pub(crate) fn accept_connect_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<AcceptConnect>()
}

/// The OpenAPI schema of `POST /v1/owner/federation/connect/accept`'s answer
/// (FIX 11611): [`ConnectAccepted`].
pub(crate) fn connect_accepted_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ConnectAccepted>()
}

/// `GET /v1/owner/federation/connect`: this vault's id and host key, what a
/// peer's owner names to offer it a pact.
async fn identity(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Value> {
    let (_, actor) = hooked_owner(&auth, &server)?;
    let identity = blocking(move || {
        hooked_row(
            server.vault(),
            actor,
            "vault.federation.connect.identity",
            EmptyRequest {},
            |_| federation_connect::identity(&server),
        )
    })
    .await?;
    Ok(Json(identity))
}

/// `POST /v1/owner/federation/connect/grants`: mints the guest grant a
/// Connect with a peer vault governs (FIX 3016), which the owner then names
/// in the offer or accept. Inert until the pact is Active.
async fn mint_grant(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<MintConnectGrant>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let minted = blocking(move || {
        hooked_row(
            server.vault(),
            actor,
            "vault.federation.connect.grants.mint",
            request,
            |request: MintConnectGrant| federation_connect::mint_grant(&server, &owner, &request),
        )
    })
    .await?;
    Ok(Json(minted))
}

/// `POST /v1/owner/federation/connect/offer`: this host's signed half of a
/// new pact with a peer vault, for the owner to carry to the peer.
async fn offer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<OfferConnect>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let offer = blocking(move || {
        hooked_row(
            server.vault(),
            actor,
            "vault.federation.connect.offer",
            request,
            |request: OfferConnect| federation_connect::offer(&server, &owner, &request),
        )
    })
    .await?;
    Ok(Json(offer))
}

/// `POST /v1/owner/federation/connect/accept`: logs the Connect the peer's
/// half signs and answers this host's half of the same pact.
async fn accept(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<AcceptConnect>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let accepted = blocking(move || {
        hooked_row(
            server.vault(),
            actor,
            "vault.federation.connect.accept",
            request,
            |request: AcceptConnect| federation_connect::accept(&server, &owner, &request),
        )
    })
    .await?;
    Ok(Json(accepted))
}
