//! `/v1/owner/widen-proposals`: the owner lists the context-widen proposals
//! agents raised, and approves or declines one as the board above
//! (`oneiron::agent_dispatch::widen_doors`). The engine keeps the board
//! proof and the approve-once consent.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::agent_dispatch::widen_doors::{
    self, WidenProposalAnswer, WidenProposalView, WidenProposalsRequest, WidenProposalsView,
};

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::OwnerResult;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/widen-proposals", get(list))
        .route("/widen-proposals/approve", post(approve))
        .route("/widen-proposals/decline", post(decline))
}

/// `GET /v1/owner/widen-proposals[?state=pending|approved|declined]`: the
/// proposals, newest first.
async fn list(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<WidenProposalsRequest>, QueryRejection>,
) -> OwnerReply<WidenProposalsView> {
    let owner = owner(&auth, &server)?;
    let request = query_params(query)?;
    let view = blocking(move || -> OwnerResult<WidenProposalsView> {
        Ok(widen_doors::widen_proposals_as_owner(
            server.vault(),
            &owner,
            &request,
        )?)
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/widen-proposals/approve`: widens the parent's slice and
/// enqueues the child.
async fn approve(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<WidenProposalAnswer>, JsonRejection>,
) -> OwnerReply<WidenProposalView> {
    let owner = owner(&auth, &server)?;
    let answer = json_payload(payload)?;
    let view = blocking(move || -> OwnerResult<WidenProposalView> {
        Ok(widen_doors::approve_widen_proposal_as_owner(
            server.vault(),
            &owner,
            &answer,
        )?)
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/widen-proposals/decline`: refuses the proposal for good.
async fn decline(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<WidenProposalAnswer>, JsonRejection>,
) -> OwnerReply<WidenProposalView> {
    let owner = owner(&auth, &server)?;
    let answer = json_payload(payload)?;
    let view = blocking(move || -> OwnerResult<WidenProposalView> {
        Ok(widen_doors::decline_widen_proposal_as_owner(
            server.vault(),
            &owner,
            &answer,
        )?)
    })
    .await?;
    Ok(Json(view))
}
