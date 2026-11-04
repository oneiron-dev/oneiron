//! `/v1/owner/packs/hooks/proposals`: an agent's hook that asks wider than
//! its own ceiling (ARCH-0080 §10: Skip, Ask or Rewrite on another actor's
//! verbs, or blocking) waits here for the owner. The agent's put bound it at
//! the agent's ceiling; the owner approves the binding it asked for, as the
//! owner's own act, or discards the ask.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::skill_hub::pack_catalog::PackHookProposal;
use serde::Deserialize;

use super::super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/packs/hooks/proposals",
                summary: "Every agent hook that asked wider than its own ceiling (ARCH-0080 §10), settled or not.",
                row: None,
            },
            get(proposals),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/hooks/proposals/approve",
                summary: "Bind an agent's hook as it asked, as the owner's own act; it still runs as its agent.",
                row: None,
            },
            post(approve),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/packs/hooks/proposals/discard",
                summary: "Decline an agent's wider ask; its binding stays at the agent's ceiling.",
                row: None,
            },
            post(discard),
        ),
    ]
}

/// The owner's answer to one proposal.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct HookProposalAnswer {
    /// The binding claim the proposal widens, as 32 hex.
    binding: String,
}

/// The OpenAPI schema of the proposal answers' body, shared by
/// `POST /v1/owner/packs/hooks/proposals/approve` and `/discard`:
/// [`HookProposalAnswer`].
pub(crate) fn hook_proposal_answer_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<HookProposalAnswer>()
}

/// The OpenAPI schema of the proposal answers' reply: the settled
/// [`PackHookProposal`].
pub(crate) fn hook_proposal_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PackHookProposal>()
}

/// `GET /v1/owner/packs/hooks/proposals`: every agent hook proposal, by
/// binding, with where it stands.
async fn proposals(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<PackHookProposal>> {
    owner(&auth, &server)?;
    let rows = blocking(move || Ok(server.vault().pack_hook_proposals()?)).await?;
    Ok(Json(rows))
}

/// `POST /v1/owner/packs/hooks/proposals/approve`: the hook's binding is
/// written again at the selector the agent asked, under the owner's stamp.
async fn approve(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<HookProposalAnswer>,
) -> OwnerReply<PackHookProposal> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let approved = blocking(move || {
        let binding = super::entity_id(&request.binding, "binding")?;
        Ok(server.vault().approve_pack_hook_proposal(&owner, binding)?)
    })
    .await?;
    Ok(Json(approved))
}

/// `POST /v1/owner/packs/hooks/proposals/discard`: the ask is declined and
/// the binding stays as the agent's put bound it.
async fn discard(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<HookProposalAnswer>,
) -> OwnerReply<PackHookProposal> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let discarded = blocking(move || {
        let binding = super::entity_id(&request.binding, "binding")?;
        Ok(server.vault().discard_pack_hook_proposal(&owner, binding)?)
    })
    .await?;
    Ok(Json(discarded))
}
