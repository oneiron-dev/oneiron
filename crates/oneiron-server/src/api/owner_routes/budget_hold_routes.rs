//! `/v1/owner/runs/hold`: the owner reads a run its budget held (OF-541,
//! ARCH-0079 #budget) and resumes it. The hold's inbox row is an Ask whose
//! `source.result` names the run's root attempt; this door serves what that
//! row points at: the hold's notice text, why it held, the results the run
//! saved and whether its spend scope has spend left. A resume is the
//! ordinary `Resume` intervention on every attempt the hold still parks.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::agent_dispatch::{AgentDispatcher, BudgetHoldState, PartialResultHold};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::run_tree::parse_attempt_id_param;
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/runs/hold", get(hold))
        .route("/runs/hold/resume", post(resume))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeldRun {
    /// The run's root attempt, as the hold's inbox row names it.
    run: String,
}

/// One held run as its owner reads it.
#[derive(Debug, Serialize)]
struct HeldRunView {
    run: String,
    state: BudgetHoldState,
    reason: String,
    /// The notice the host delivered to the owners' inboxes.
    notice: Option<String>,
    notice_delivered_at: Option<u64>,
    /// Saved result handles the run produced before the hold.
    partial_result_refs: Vec<String>,
    /// The attempts the hold parks, each resuming from its checkpoint.
    held: Vec<String>,
    /// The plan the run ran, as the hold saved it.
    plan: Option<serde_json::Value>,
    /// Whether the run's spend scope has spend left now.
    resume_ready: bool,
    warned_at: Option<u64>,
    held_at: Option<u64>,
    resumed_at: Option<u64>,
    resumed_by: Option<String>,
}

impl HeldRunView {
    fn of(hold: PartialResultHold) -> OwnerResult<Self> {
        let hex = |id: oneiron::AttemptId| {
            id.as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        Ok(Self {
            run: hex(hold.root_attempt),
            state: hold.state,
            reason: hold.reason,
            notice_delivered_at: hold.notice.as_ref().and_then(|notice| notice.delivered_at),
            notice: hold.notice.map(|notice| notice.text),
            partial_result_refs: hold.partial_result_refs,
            held: hold.held.iter().map(|held| hex(held.attempt)).collect(),
            plan: hold
                .plan
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| OwnerError::Invalid("the held run's plan does not read".to_owned()))?,
            resume_ready: hold.resume_ready,
            warned_at: hold.warned_at,
            held_at: hold.held_at,
            resumed_at: hold.resumed_at,
            resumed_by: hold.resumed_by,
        })
    }
}

/// `GET /v1/owner/runs/hold?run=<root attempt hex>`: the run's hold, with
/// whether its spend scope has spend left read again now.
async fn hold(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<HeldRun>, QueryRejection>,
) -> OwnerReply<HeldRunView> {
    owner(&auth, &server)?;
    let request = query_params(query)?;
    let root = parse_attempt_id_param(&request.run, "run")?;
    let view = blocking(move || -> OwnerResult<HeldRunView> {
        AgentDispatcher::new(server.vault())
            .refresh_budget_hold(root)?
            .ok_or(OwnerError::NotFound("budget_hold", request.run))
            .and_then(HeldRunView::of)
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/runs/hold/resume` `{run}`: resumes the held run as the
/// owner. Each attempt it still parks is queued again and resumes from its
/// checkpoint; one someone else paused or settled since is left as it is.
async fn resume(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<HeldRun>, JsonRejection>,
) -> OwnerReply<HeldRunView> {
    owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let root = parse_attempt_id_param(&request.run, "run")?;
    let actor = auth.principal().to_owned();
    let view = blocking(move || -> OwnerResult<HeldRunView> {
        let dispatcher = AgentDispatcher::new(server.vault());
        if dispatcher.plan_hold(root)?.is_none() {
            return Err(OwnerError::NotFound("budget_hold", request.run));
        }
        HeldRunView::of(dispatcher.resume_budget_hold(
            root,
            &actor,
            oneiron_vault_contract::now_ts(),
        )?)
    })
    .await?;
    Ok(Json(view))
}
