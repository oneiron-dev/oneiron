//! `/v1/owner/secrets/lift*`: the owner's side of the historical lift sweep's
//! proposals (OF-067). A run that leaves proposals open raises one inbox Ask
//! pointing here and at `vault.secrets.lift_history`. The owner reads the
//! sweep's state (the run in progress, the last receipt, the open proposals
//! counted by cause) and closes one proposal with a reason: `not_a_secret`,
//! `rotated` or `accepted`. The close writes its Gate receipt in the engine;
//! nothing here reads a value.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::policy_model::{
    SecretLiftClose, SecretLiftHistoryProposal, SecretLiftRequest, SecretLiftStatus,
    secret_lift_as_owner,
};

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::OwnerResult;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/secrets/lift", get(status))
        .route("/secrets/lift/close", post(close))
}

/// `GET /v1/owner/secrets/lift`: the run in progress, the last run's receipt
/// and the open proposals, counted by cause.
async fn status(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<SecretLiftStatus> {
    let owner = owner(&auth, &server)?;
    let status = blocking(move || -> OwnerResult<SecretLiftStatus> {
        Ok(secret_lift_as_owner(
            server.vault(),
            &owner,
            &SecretLiftRequest::default(),
        )?)
    })
    .await?;
    Ok(Json(status))
}

/// `POST /v1/owner/secrets/lift/close` with `{"proposal", "reason"}`: closes
/// one open proposal, by its `id`, and returns it as it now stands.
async fn close(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SecretLiftClose>, JsonRejection>,
) -> OwnerReply<SecretLiftHistoryProposal> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let closed = blocking(move || -> OwnerResult<SecretLiftHistoryProposal> {
        Ok(server
            .vault()
            .close_secret_lift_proposal(&owner, &request.proposal, request.reason)?)
    })
    .await?;
    Ok(Json(closed))
}
