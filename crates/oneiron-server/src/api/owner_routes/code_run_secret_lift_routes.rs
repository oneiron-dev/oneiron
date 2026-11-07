//! Value-free code-result secret lift proposals on the owner HTTP door.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::code_run::{
    CodeRunRoomSecretLiftRequest, CodeRunSecretLiftDismiss, CodeRunSecretLiftProposalView,
    CodeRunSecretLiftRequest, CodeRunSecretLiftStatus,
};

use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::OwnerResult;
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/secrets/code-run-room-lifts",
                summary: "Lists positive MESSAGE-linked lift proposals in one room overlay without reading a body or preview.",
                row: None,
                shape: None,
            },
            get(list_room),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/secrets/code-run-lifts",
                summary: "Lists the owner's open code-result secret lift proposals without reading a value.",
                row: None,
                shape: None,
            },
            get(list),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/secrets/code-run-lifts/dismiss",
                summary: "Dismisses one proposal with a receipt, leaving its secret and taint marks unchanged.",
                row: None,
                shape: Some(RestShape::json(dismiss_schema, status_schema)),
            },
            post(dismiss),
        ),
    ]
}

fn dismiss_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<CodeRunSecretLiftDismiss>()
}

fn status_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<CodeRunSecretLiftStatus>()
}

async fn list(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<CodeRunSecretLiftStatus> {
    let owner = owner(&auth, &server)?;
    let status = blocking(move || -> OwnerResult<CodeRunSecretLiftStatus> {
        Ok(server
            .vault()
            .code_run_secret_lifts_as_owner(&owner, &CodeRunSecretLiftRequest::default())?)
    })
    .await?;
    Ok(Json(status))
}

async fn dismiss(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<CodeRunSecretLiftDismiss>,
) -> OwnerReply<CodeRunSecretLiftStatus> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let status = blocking(move || -> OwnerResult<CodeRunSecretLiftStatus> {
        Ok(server.vault().code_run_secret_lifts_as_owner(
            &owner,
            &CodeRunSecretLiftRequest {
                dismiss: Some(request),
            },
        )?)
    })
    .await?;
    Ok(Json(status))
}

async fn list_room(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Query(request): Query<CodeRunRoomSecretLiftRequest>,
) -> OwnerReply<Vec<CodeRunSecretLiftProposalView>> {
    let owner = owner(&auth, &server)?;
    let proposals = blocking(move || -> OwnerResult<Vec<CodeRunSecretLiftProposalView>> {
        Ok(server
            .vault()
            .code_run_room_secret_lifts_as_owner(&owner, &request)?)
    })
    .await?;
    Ok(Json(proposals))
}
