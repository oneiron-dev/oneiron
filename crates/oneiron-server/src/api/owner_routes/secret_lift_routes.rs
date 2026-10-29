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
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::policy_model::{
    SecretLiftClose, SecretLiftHistoryProposal, SecretLiftRequest, SecretLiftStatus,
    secret_lift_as_owner_toward,
};

use super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
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
    let destination = auth.destination();
    let status = blocking(move || -> OwnerResult<SecretLiftStatus> {
        Ok(secret_lift_as_owner_toward(
            server.vault(),
            &owner,
            &SecretLiftRequest::default(),
            &destination,
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
    payload: OwnerJsonBody<SecretLiftClose>,
) -> OwnerReply<SecretLiftHistoryProposal> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let closed = blocking(move || -> OwnerResult<SecretLiftHistoryProposal> {
        Ok(server
            .vault()
            .close_secret_lift_proposal(&owner, &request.proposal, request.reason)?)
    })
    .await?;
    Ok(Json(closed))
}
