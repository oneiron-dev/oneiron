//! `/v1/owner/craft-candidates`: the owner lists the craft notes residents'
//! dreaming proposed about themselves, and approves or rejects one on its
//! card (`oneiron::actor_claims`, OF-490). The engine writes the verdict, the
//! candidate's close and the decision receipt in one write.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::actor_claims::{
    self, CraftCandidateAnswer, CraftCandidatesRequest, CraftCandidatesView, CraftVerdictView,
};

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/craft-candidates", get(list))
        .route("/craft-candidates/answer", post(answer))
}

/// `GET /v1/owner/craft-candidates[?resident=<hex>]`: the candidates waiting
/// on a verdict, newest first.
async fn list(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<CraftCandidatesRequest>, QueryRejection>,
) -> OwnerReply<CraftCandidatesView> {
    let owner = owner(&auth, &server)?;
    let request = query_params(query)?;
    let view = blocking(move || -> OwnerResult<CraftCandidatesView> {
        Ok(actor_claims::craft_candidates_as_owner(
            server.vault(),
            &owner,
            &request,
        )?)
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/craft-candidates/answer`: the owner's verdict on one
/// candidate, bound to the content hash its card showed.
async fn answer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CraftCandidateAnswer>, JsonRejection>,
) -> OwnerReply<CraftVerdictView> {
    let owner = owner(&auth, &server)?;
    let answer = json_payload(payload)?;
    let view = blocking(move || -> OwnerResult<CraftVerdictView> {
        actor_claims::answer_craft_candidate_as_owner(server.vault(), &owner, &answer).map_err(
            |error| match error {
                oneiron::Error::EntityNotFound => {
                    OwnerError::NotFound("craft candidate", answer.candidate_id.clone())
                }
                error => error.into(),
            },
        )
    })
    .await?;
    Ok(Json(view))
}
