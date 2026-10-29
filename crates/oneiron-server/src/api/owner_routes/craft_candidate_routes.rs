//! `/v1/owner/craft-candidates`: the owner lists the craft notes residents'
//! dreaming proposed about themselves, and approves or rejects one on its
//! card (`oneiron::actor_claims`, OF-490). The engine writes the verdict, the
//! candidate's close and the decision receipt in one write. Each route runs
//! its `vault.craft_candidates*` row's verb hooks once around the call, as
//! the owner in person (FIX 8201).

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::actor_claims::{
    self, CraftCandidateAnswer, CraftCandidatesRequest, CraftCandidatesView, CraftVerdictView,
};
use serde_json::Value;

use super::{OwnerReply, blocking, hooked_owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, hooked_row};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/craft-candidates", get(list))
        .route("/craft-candidates/answer", post(answer))
}

/// The OpenAPI schema of `POST /v1/owner/craft-candidates/answer`'s body
/// (FIX 11611): [`CraftCandidateAnswer`].
pub(crate) fn craft_answer_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<CraftCandidateAnswer>()
}

/// The OpenAPI schema of `POST /v1/owner/craft-candidates/answer`'s answer
/// (FIX 11611): the verdict as it landed, [`CraftVerdictView`].
pub(crate) fn craft_verdict_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<CraftVerdictView>()
}

/// `GET /v1/owner/craft-candidates[?resident=<hex>]`: the candidates waiting
/// on a verdict, newest first.
async fn list(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<CraftCandidatesRequest>, QueryRejection>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = query_params(query)?;
    let view = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.craft_candidates",
            request,
            |request: CraftCandidatesRequest| -> OwnerResult<CraftCandidatesView> {
                Ok(actor_claims::craft_candidates_as_owner(
                    vault, &owner, &request,
                )?)
            },
        )
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/craft-candidates/answer`: the owner's verdict on one
/// candidate, bound to the content hash its card showed.
async fn answer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<CraftCandidateAnswer>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let answer = payload.read(&server).await?;
    let view = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.craft_candidates.answer",
            answer,
            |answer: CraftCandidateAnswer| -> OwnerResult<CraftVerdictView> {
                actor_claims::answer_craft_candidate_as_owner(vault, &owner, &answer).map_err(
                    |error| match error {
                        oneiron::Error::EntityNotFound => {
                            OwnerError::NotFound("craft candidate", answer.candidate_id.clone())
                        }
                        error => error.into(),
                    },
                )
            },
        )
    })
    .await?;
    Ok(Json(view))
}
