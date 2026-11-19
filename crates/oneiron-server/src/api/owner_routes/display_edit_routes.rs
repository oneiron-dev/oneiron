//! `/v1/owner/display-edits`: the owner's answers to his agents' display-edit
//! proposals (FIX [SECRETS-LABEL-PURPOSE-VERBS], [DEVICE-DISPLAY-NAME]; Engine
//! RULING DISPLAY-EDIT-PROPOSAL-SCOPE = A). `GET /display-edits` lists every
//! open proposal; `POST /display-edits/accept` runs his own door for the
//! proposed label, purpose or machine name, as his act, and closes the
//! proposal; `POST /display-edits/decline` closes it and changes nothing. Each
//! runs its SDK row (`vault.display_edits.list`, `.accept`, `.decline`) inside
//! the row's verb hooks, as the owner in person; an agent files a proposal at
//! `self.display_edits.propose` and never reaches these.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::task_verb::sdk::{self, DisplayEditAnswerRequest, EmptyRequest};
use serde_json::Value;

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, hooked_owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{hooked_row, memory_refusal};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/display-edits",
                summary: "Every open display-edit proposal an agent filed, newest first (FIX SECRETS-LABEL-PURPOSE-VERBS, DEVICE-DISPLAY-NAME): `proposals`, each with its `id`, `target` (`secret_label`, `secret_purpose` or `machine_name`), `subject` (a secret's handle or a machine's 32 hex), the proposed `value` (null: clear it), the agent's `why`, the `proposer` and `proposed_at`.",
                row: Some("vault.display_edits.list"),
                shape: None,
            },
            get(list_proposals),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/display-edits/accept",
                summary: "The owner accepts a display-edit proposal (`id`, 32 hex): his own door sets or clears the label, purpose or machine name as his act, and the proposal closes. Answers the proposal and the act's Gate receipt; refuses what that door refuses.",
                row: Some("vault.display_edits.accept"),
                shape: None,
            },
            post(accept_proposal),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/display-edits/decline",
                summary: "The owner declines a display-edit proposal (`id`, 32 hex): it closes, and nothing it names changes. Answers the proposal.",
                row: Some("vault.display_edits.decline"),
                shape: None,
            },
            post(decline_proposal),
        ),
    ]
}

/// `GET /v1/owner/display-edits`: every open proposal, newest first.
async fn list_proposals(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let response = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.display_edits.list",
            EmptyRequest {},
            |_| sdk::list_display_edits_as(vault, &owner).map_err(memory_refusal),
        )
    })
    .await?;
    Ok(Json(response))
}

/// `POST /v1/owner/display-edits/accept`: the owner's door makes the
/// proposed edit, and the proposal closes.
async fn accept_proposal(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<DisplayEditAnswerRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let response = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.display_edits.accept",
            request,
            |request: DisplayEditAnswerRequest| {
                sdk::accept_display_edit_as(vault, &owner, request).map_err(memory_refusal)
            },
        )
    })
    .await?;
    Ok(Json(response))
}

/// `POST /v1/owner/display-edits/decline`: the proposal closes, and nothing
/// it names changes.
async fn decline_proposal(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<DisplayEditAnswerRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let response = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.display_edits.decline",
            request,
            |request: DisplayEditAnswerRequest| {
                sdk::decline_display_edit_as(vault, &owner, request).map_err(memory_refusal)
            },
        )
    })
    .await?;
    Ok(Json(response))
}
