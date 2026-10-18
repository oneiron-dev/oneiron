//! `/v1/owner/support-grants`: the customer's support grants (OF-606),
//! behind the same owner door as every other owner route. On our hosted
//! cloud the operator root acts as nobody inside a customer's vault (FIX
//! 2222); the customer's owner instead mints our support person or agent a
//! time-limited, revocable grant, lists them, and revokes one. A managed
//! customer reaches this door with the managed owner proof, never the
//! operator's root; a support credential never reaches it at all, its own
//! grant included. Mint and revoke hand the engine this host's slip issuer
//! (`api/pairing.rs`'s), which signs only after the engine revalidated the
//! owner in its own writer. Each route runs its `vault.support_grants.*`
//! row's verb hooks once around the one engine operation the SDK and MCP
//! doors also call.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::task_verb::sdk::{
    self, SupportGrantListRequest, SupportGrantMintAnswer, SupportGrantMintRequest,
    SupportGrantRevokeAnswer, SupportGrantRevokeRequest,
};
use serde_json::Value;

use super::{OwnerReply, blocking, hooked_owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, hooked_row, memory_refusal};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/support-grants", get(list))
        .route("/support-grants/mint", post(mint))
        .route("/support-grants/revoke", post(revoke))
}

/// What a route answers when this host holds no slip-signing key.
fn no_issuer() -> OwnerError {
    OwnerError::Refused("this host holds no signing key for support grants".to_owned())
}

/// `POST /v1/owner/support-grants/mint`: mints one support grant for a live,
/// non-owner PERSON of the vault, bound to the support party's own public
/// key, inside explicit bounds and for at most a day. Answers the
/// credential (no private key) and the grant.
async fn mint(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SupportGrantMintRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let response = blocking(move || {
        hooked_row(
            server.vault(),
            actor,
            "vault.support_grants.mint",
            request,
            |request: SupportGrantMintRequest| -> OwnerResult<SupportGrantMintAnswer> {
                crate::api::pairing::with_issuer(&server, |issuer| {
                    Ok(sdk::mint_support_grant_as(
                        server.vault(),
                        &owner,
                        issuer,
                        request,
                    ))
                })
                .map_err(|_| no_issuer())?
                .map_err(memory_refusal)
            },
        )
    })
    .await?;
    Ok(Json(response))
}

/// `GET /v1/owner/support-grants?include_inactive=&limit=`: the vault's
/// support grants, newest first; active ones unless `include_inactive`.
async fn list(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<SupportGrantListRequest>, QueryRejection>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = query_params(query)?;
    let response = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.support_grants.list",
            request,
            |request: SupportGrantListRequest| {
                sdk::list_support_grants_as(vault, &owner, request).map_err(memory_refusal)
            },
        )
    })
    .await?;
    Ok(Json(response))
}

/// `POST /v1/owner/support-grants/revoke` with `{"grant_ref": "<hex>"}`:
/// revokes one support grant. A repeat answers `changed: false`; what
/// support already read is not recalled, and the answer says so.
async fn revoke(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SupportGrantRevokeRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let response = blocking(move || {
        hooked_row(
            server.vault(),
            actor,
            "vault.support_grants.revoke",
            request,
            |request: SupportGrantRevokeRequest| -> OwnerResult<SupportGrantRevokeAnswer> {
                crate::api::pairing::with_issuer(&server, |issuer| {
                    Ok(sdk::revoke_support_grant_as(
                        server.vault(),
                        &owner,
                        issuer,
                        request,
                    ))
                })
                .map_err(|_| no_issuer())?
                .map_err(memory_refusal)
            },
        )
    })
    .await?;
    Ok(Json(response))
}
