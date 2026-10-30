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

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "post",
                path: "/feedback/triage/run",
                summary: "Queues the Coach's feedback sweep now (`{}`), joining one already queued: each open-inbox note not yet handed off gets its own triage job on the bound skill, whose findings land Proposed in the run tray. Answers `{attempt}`; the sweep completing is not each job finishing.",
                row: None,
            },
            post(run),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/feedback/triage/status",
                summary: "One feedback sweep's status (`attempt`, 32 hex): its state and last error, the binding, each source's continuation, each revision it handed off or queued again with its job's state and committed result refs, and the holds (`skill_unbound`, each revision still unacknowledged). Not found when the queue holds no such attempt.",
                row: None,
            },
            get(status),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/feedback/triage/binding",
                summary: "The skill the Coach's feedback triage runs (OF-420): `skill` (32 hex, null until the owner binds one), the `revision` a change names as `seen` (0 while never set) and `set_at`. With no skill bound every triage run fails and its status holds `skill_unbound`.",
                row: None,
            },
            get(binding),
        ),
        (
            OwnerRoute {
                method: "put",
                path: "/feedback/triage/binding",
                summary: "Binds the SKILL the feedback triage runs (`skill`, 32 hex; null unbinds) at the `seen` revision the owner read; a binding that moved since is refused and nothing changes. Answers the binding.",
                row: None,
            },
            put(set_binding),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/feedback/delivery/run",
                summary: "Queues the Coach's publisher delivery now (`{}`), joining one already queued: every report routed to a publisher gets its content-free ED-08 issue signature, sent to the endpoint the owner bound while \"Help improve Oneiron\" and the publisher dial are both on. Text never leaves this way. Answers `{attempt}`.",
                row: None,
            },
            post(delivery_run),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/feedback/delivery/status",
                summary: "One report issue's signature delivery (`issue_ref`, 32 hex): whether it is routed to a publisher, the publisher's binding, and its lane (key, frozen signature and send, hold, receipt and outcome). Holds: `metadata_unresolved` with its reason, `endpoint_unbound`, `destination_unsupported`, `changed_binding`, `withheld`. Not found when the vault holds no such issue.",
                row: None,
            },
            get(delivery_status),
        ),
        (
            OwnerRoute {
                method: "put",
                path: "/feedback/delivery/binding",
                summary: "Binds a publisher (`publisher_ref`) to this server's feedback destination, its channel and exact endpoint as configured now (`bound: true`), or unbinds it (`false`); binding needs a configured destination. Its content-free issue signatures go only there, and a lane that froze another destination holds as `changed_binding`, never redirected. Answers `{publisher_ref, endpoint}`.",
                row: None,
            },
            put(delivery_binding),
        ),
    ]
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
