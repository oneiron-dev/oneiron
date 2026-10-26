//! `/v1/owner/connectors/slate/redraft` (FIX 987): the owner asks the host's
//! configured drafter to re-draft one connector grant slate from his
//! instruction (ARCH-0072 "re-draft"). It proposes changed rows with their
//! rationale at the slate's revision; nothing is stamped, activated or
//! granted, and the owner accepts a proposal through `/slate/accept` at that
//! revision. A host with no drafter answers `unavailable` and the slate is
//! unchanged. The same service backs `vault.connectors.slates.redraft`.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::task_verb::sdk::{ConnectorSlateRedraftReply, ConnectorSlateRedraftRequest};

use super::connector_admission_routes::{engine, with_slate_drafter};
use super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/connectors/slate/redraft", post(redraft))
}

/// `POST /v1/owner/connectors/slate/redraft`: the owner's re-draft request.
async fn redraft(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ConnectorSlateRedraftRequest>,
) -> OwnerReply<ConnectorSlateRedraftReply> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reply = blocking(move || redraft_slate(&server, &owner, request).map_err(engine)).await?;
    Ok(Json(reply))
}

/// The owner's re-draft of the slate `request` names, at the revision he
/// reviewed (a slate that moved since refuses), through the host's
/// configured drafter: model work, so its callers run it off the runtime.
/// With no drafter configured it proposes nothing.
///
/// # Errors
/// A malformed ref, a slate that is gone or moved, an instruction the
/// engine refuses, storage errors.
pub(crate) fn redraft_slate(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    request: ConnectorSlateRedraftRequest,
) -> oneiron::Result<ConnectorSlateRedraftReply> {
    let slate_id = EntityId::from_hex(&request.slate_ref)?;
    let vault = server.vault();
    let slate = vault
        .connector_slate(slate_id)?
        .ok_or(oneiron::Error::EntityNotFound)?;
    if slate.revision() != request.expected_revision {
        return Err(oneiron::Error::ConcurrentWrite("connector slate revision"));
    }
    with_slate_drafter(server, owner, |drafter| match drafter {
        Some(drafter) => vault
            .redraft_connector_slate(slate_id, &request.instruction, drafter)
            .map(ConnectorSlateRedraftReply::proposed),
        None => Ok(ConnectorSlateRedraftReply::unavailable()),
    })
}
