//! `/v1/owner/feedback/triage`: the owner runs the Coach's feedback triage
//! now, reads one run's status, and binds the skill it runs (OF-420 T1;
//! `oneiron::feedback`). A run queues the production sweep on the Coach's
//! host queue, joining one already queued, and answers its attempt; the
//! status names the sweep's and each triage job's state, the inbox
//! continuation, each committed result and what holds triage back. Nothing
//! here reads, moves or closes a note, and the inbox's own doors are
//! unchanged.
//!
//! `/v1/owner/feedback/delivery` sits beside it: the owner runs the Coach's
//! publisher delivery of content-free issue signatures now (OF-420, FIX
//! 739), reads one issue's delivery, and binds a publisher to this server's
//! feedback destination. Nothing here sends a report's text.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post, put};
use oneiron::feedback::{
    FeedbackTriageBinding, FeedbackTriageBindingRequest, FeedbackTriageRun,
    FeedbackTriageRunRequest, FeedbackTriageStatus, FeedbackTriageStatusRequest, ReportDeliveryRun,
    ReportDeliveryRunRequest, ReportDeliveryStatus, ReportDeliveryStatusRequest,
    ReportPublisherBinding, ReportPublisherBindingRequest, ReportPublisherEndpoint,
};

use super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/feedback/triage/run", post(run))
        .route("/feedback/triage/status", get(status))
        .route("/feedback/triage/binding", get(binding).put(set_binding))
        .route("/feedback/delivery/run", post(delivery_run))
        .route("/feedback/delivery/status", get(delivery_status))
        .route("/feedback/delivery/binding", put(delivery_binding))
}

/// `POST /v1/owner/feedback/triage/run` with `{}`: queues the sweep now and
/// answers `{attempt}`. Its completion is the sweep's, not each triage
/// job's: read the status for those.
async fn run(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<FeedbackTriageRunRequest>,
) -> OwnerReply<FeedbackTriageRun> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let run = blocking(move || -> OwnerResult<FeedbackTriageRun> {
        Ok(server.vault().queue_feedback_triage(&owner, request)?)
    })
    .await?;
    Ok(Json(run))
}

/// `GET /v1/owner/feedback/triage/status?attempt=<32 hex>`: one sweep's
/// status, with every repository `[feedback.triage]` binds, so one never
/// swept shows (FIX 7632); not found when the queue holds no such attempt.
async fn status(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<FeedbackTriageStatusRequest>, QueryRejection>,
) -> OwnerReply<FeedbackTriageStatus> {
    let owner = owner(&auth, &server)?;
    let request = query_params(query)?;
    let status = blocking(move || -> OwnerResult<FeedbackTriageStatus> {
        let mut status = server
            .vault()
            .feedback_triage_status(&owner, &request)?
            .ok_or_else(|| OwnerError::NotFound("feedback triage run", request.attempt.to_hex()))?;
        status.bound_sources = server
            .feedback_triage
            .github_sources
            .iter()
            .filter_map(|endpoint| crate::config::github_issue_source(endpoint.as_str()))
            .collect();
        Ok(status)
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
    payload: OwnerJsonBody<FeedbackTriageBindingRequest>,
) -> OwnerReply<FeedbackTriageBinding> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let binding = blocking(move || -> OwnerResult<FeedbackTriageBinding> {
        Ok(server
            .vault()
            .set_feedback_triage_binding(&owner, &request)?)
    })
    .await?;
    Ok(Json(binding))
}

/// `POST /v1/owner/feedback/delivery/run` with `{}`: queues the Coach's
/// publisher delivery now, joining one already queued, and answers
/// `{attempt}`. Read each issue's status for what it sent or holds.
async fn delivery_run(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ReportDeliveryRunRequest>,
) -> OwnerReply<ReportDeliveryRun> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let run = blocking(move || -> OwnerResult<ReportDeliveryRun> {
        Ok(server
            .vault()
            .queue_feedback_report_delivery(&owner, request)?)
    })
    .await?;
    Ok(Json(run))
}

/// `GET /v1/owner/feedback/delivery/status?issue_ref=<32 hex>`: one issue's
/// signature delivery; not found when the vault holds no such issue.
async fn delivery_status(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<ReportDeliveryStatusRequest>, QueryRejection>,
) -> OwnerReply<ReportDeliveryStatus> {
    let owner = owner(&auth, &server)?;
    let request = query_params(query)?;
    let status = blocking(move || -> OwnerResult<ReportDeliveryStatus> {
        server
            .vault()
            .report_delivery_status(&owner, &request)?
            .ok_or_else(|| OwnerError::NotFound("report issue", request.issue_ref.clone()))
    })
    .await?;
    Ok(Json(status))
}

/// `PUT /v1/owner/feedback/delivery/binding` with `{publisher_ref, bound}`:
/// binds the publisher to this server's feedback destination, its channel
/// and exact endpoint as configured now, or unbinds it with `false`.
/// Binding needs a configured destination. Answers the binding.
async fn delivery_binding(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ReportPublisherBindingRequest>,
) -> OwnerReply<ReportPublisherBinding> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let endpoint = if request.bound {
        let route = super::feedback_host(&server)?.config.route();
        Some(ReportPublisherEndpoint {
            channel: route.channel,
            endpoint: route.target,
        })
    } else {
        None
    };
    let binding = blocking(move || -> OwnerResult<ReportPublisherBinding> {
        Ok(server.vault().set_report_publisher_endpoint(
            &owner,
            &request.publisher_ref,
            endpoint,
        )?)
    })
    .await?;
    Ok(Json(binding))
}
