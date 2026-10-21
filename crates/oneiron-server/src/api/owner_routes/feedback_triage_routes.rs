//! `/v1/owner/feedback/triage`: the owner runs the Coach's feedback triage
//! now, reads one run's status, and binds the skill it runs (OF-420 T1;
//! `oneiron::feedback`). A run queues the production sweep on the Coach's
//! host queue, joining one already queued, and answers its attempt; the
//! status names the sweep's and each triage job's state, the inbox
//! continuation, each committed result and what holds triage back. Nothing
//! here reads, moves or closes a note, and the inbox's own doors are
//! unchanged.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::feedback::{
    FeedbackTriageBinding, FeedbackTriageBindingRequest, FeedbackTriageRun,
    FeedbackTriageRunRequest, FeedbackTriageStatus, FeedbackTriageStatusRequest,
};

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/feedback/triage/run", post(run))
        .route("/feedback/triage/status", get(status))
        .route("/feedback/triage/binding", get(binding).put(set_binding))
}

/// `POST /v1/owner/feedback/triage/run` with `{}`: queues the sweep now and
/// answers `{attempt}`. Its completion is the sweep's, not each triage
/// job's: read the status for those.
async fn run(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<FeedbackTriageRunRequest>, JsonRejection>,
) -> OwnerReply<FeedbackTriageRun> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let run = blocking(move || -> OwnerResult<FeedbackTriageRun> {
        Ok(server.vault().queue_feedback_triage(&owner, request)?)
    })
    .await?;
    Ok(Json(run))
}

/// `GET /v1/owner/feedback/triage/status?attempt=<32 hex>`: one sweep's
/// status; not found when the queue holds no such attempt.
async fn status(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<FeedbackTriageStatusRequest>, QueryRejection>,
) -> OwnerReply<FeedbackTriageStatus> {
    let owner = owner(&auth, &server)?;
    let request = query_params(query)?;
    let status = blocking(move || -> OwnerResult<FeedbackTriageStatus> {
        server
            .vault()
            .feedback_triage_status(&owner, &request)?
            .ok_or_else(|| OwnerError::NotFound("feedback triage run", request.attempt.to_hex()))
    })
    .await?;
    Ok(Json(status))
}

/// `GET /v1/owner/feedback/triage/binding`: the skill the triage runs, with
/// the revision a change names as `seen`.
async fn binding(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<FeedbackTriageBinding> {
    let owner = owner(&auth, &server)?;
    let binding = blocking(move || -> OwnerResult<FeedbackTriageBinding> {
        Ok(server.vault().feedback_triage_binding(&owner)?)
    })
    .await?;
    Ok(Json(binding))
}

/// `PUT /v1/owner/feedback/triage/binding` with `{skill, seen}`: binds the
/// skill (null unbinds) at the revision the owner read; a binding that
/// moved since is refused and nothing changes.
async fn set_binding(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<FeedbackTriageBindingRequest>, JsonRejection>,
) -> OwnerReply<FeedbackTriageBinding> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let binding = blocking(move || -> OwnerResult<FeedbackTriageBinding> {
        Ok(server
            .vault()
            .set_feedback_triage_binding(&owner, &request)?)
    })
    .await?;
    Ok(Json(binding))
}
