//! `/v1/owner/guests/revoke`: the owner withdraws one ask guest's access at
//! this host (OF-232), behind the same owner door as every other owner route.
//! The engine deletes the guest's grant, disconnects each live pact it still
//! governs, signed with the host's slip issuer (`api/pairing.rs`'s), and
//! keeps the withdrawal, so a repeat answers the first revoke with
//! `changed: false`. The answer carries the copied-bytes disclosure: what
//! the guest already synced is the guest's copy, never recalled.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::post;
use oneiron::receipt::{GuestRevokeResponse, project_guest_revoke};
use oneiron::task_verb::sdk::GuestRevokeRequest;
use serde_json::Value;

use super::{OwnerReply, blocking, hooked_owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, hooked_row};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/guests/revoke", post(revoke))
}

/// `POST /v1/owner/guests/revoke` with `{"grant_ref": "<hex>"}`: an unknown
/// or non-guest grant is not found, and a disconnect the fold refuses fails
/// the whole revoke.
async fn revoke(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<GuestRevokeRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let response = blocking(move || {
        hooked_row(
            server.vault(),
            actor,
            "vault.guests.revoke",
            request,
            |request: GuestRevokeRequest| -> OwnerResult<GuestRevokeResponse> {
                let outcome = crate::api::pairing::with_issuer(&server, |issuer| {
                    Ok(server
                        .vault()
                        .revoke_guest_access(&owner, issuer, request.grant_ref))
                })
                .map_err(|_| {
                    OwnerError::Refused(
                        "this host holds no signing key for the guest's pact disconnects"
                            .to_owned(),
                    )
                })??;
                Ok(project_guest_revoke(outcome))
            },
        )
    })
    .await?;
    Ok(Json(response))
}
