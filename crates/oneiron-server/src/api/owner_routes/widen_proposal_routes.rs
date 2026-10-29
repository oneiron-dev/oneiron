//! `/v1/owner/widen-proposals`: the owner lists the context-widen proposals
//! agents raised, and approves or declines one as the board above
//! (`oneiron::agent_dispatch::widen_doors`). The engine keeps the board
//! proof and the approve-once consent. Each route runs its
//! `vault.widen_proposals*` row's verb hooks once around the call, as the
//! owner in person (FIX 9479).

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::agent_dispatch::widen_doors::{
    self, WidenProposalAnswer, WidenProposalView, WidenProposalsRequest, WidenProposalsView,
};

use serde_json::Value;

use super::{OwnerReply, blocking, hooked_owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::{OwnerResult, hooked_row};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/widen-proposals", get(list))
        .route("/widen-proposals/approve", post(approve))
        .route("/widen-proposals/decline", post(decline))
}

/// The OpenAPI schema of `POST /v1/owner/widen-proposals/approve`'s body
/// (FIX 11611), shared with `/widen-proposals/decline`: [`WidenProposalAnswer`].
pub(crate) fn widen_answer_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<WidenProposalAnswer>()
}

/// The OpenAPI schema of `POST /v1/owner/widen-proposals/approve`'s answer
/// (FIX 11611), shared with `/widen-proposals/decline`: [`WidenProposalView`].
pub(crate) fn widen_proposal_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<WidenProposalView>()
}

/// `GET /v1/owner/widen-proposals[?state=pending|approved|declined]`: the
/// proposals, newest first.
async fn list(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<WidenProposalsRequest>, QueryRejection>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = query_params(query)?;
    let view = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.widen_proposals",
            request,
            |request: WidenProposalsRequest| -> OwnerResult<WidenProposalsView> {
                Ok(widen_doors::widen_proposals_as_owner(
                    vault, &owner, &request,
                )?)
            },
        )
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/widen-proposals/approve`: widens the parent's slice and
/// enqueues the child.
async fn approve(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<WidenProposalAnswer>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let answer = payload.read(&server).await?;
    let view = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.widen_proposals.approve",
            answer,
            |answer: WidenProposalAnswer| -> OwnerResult<WidenProposalView> {
                Ok(widen_doors::approve_widen_proposal_as_owner(
                    vault, &owner, &answer,
                )?)
            },
        )
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/widen-proposals/decline`: refuses the proposal for good.
async fn decline(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<WidenProposalAnswer>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let answer = payload.read(&server).await?;
    let view = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.widen_proposals.decline",
            answer,
            |answer: WidenProposalAnswer| -> OwnerResult<WidenProposalView> {
                Ok(widen_doors::decline_widen_proposal_as_owner(
                    vault, &owner, &answer,
                )?)
            },
        )
    })
    .await?;
    Ok(Json(view))
}
