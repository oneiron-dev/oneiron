//! `/v1/owner/cleanup/review` and `/v1/owner/cleanup/decide`: one open
//! cleanup proposal reviewed slot by slot with full disclosure, and decided
//! per item in one complete verdict (FIX 1758). The bodies are the
//! `vault.cleanup.review` and `vault.cleanup.decide` rows' inputs. The
//! whole-proposal accept and reject routes stay beside them.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use oneiron::EdgeActorClass;
use oneiron::vault_cleanup::{
    CleanupDecideRequest, CleanupDecideView, CleanupReviewRequest, CleanupReviewView,
};

use super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerResult, cleanup};
use crate::server::SyncServer;

/// `POST /v1/owner/cleanup/review`: `{proposal}`, answered with every slot's
/// state, evidence, revision, what accepting it does and its full content,
/// read through the owner's own reads.
pub(super) async fn review_proposal(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<CleanupReviewRequest>,
) -> OwnerReply<CleanupReviewView> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let locality = auth.locality();
    let review = blocking(move || -> OwnerResult<CleanupReviewView> {
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        let memory = vault.memory(actor, EdgeActorClass::Human).at(locality);
        cleanup::review_proposal(&memory, &owner, &request)
    })
    .await?;
    Ok(Json(review))
}

/// `POST /v1/owner/cleanup/decide`: `{proposal, choices, expected_revision?}`
/// with one choice per slot, answered with each slot's outcome and the
/// decision's digest.
pub(super) async fn decide_proposal(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<CleanupDecideRequest>,
) -> OwnerReply<CleanupDecideView> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let decided = blocking(move || cleanup::decide(server.vault(), &owner, &request)).await?;
    Ok(Json(decided))
}
