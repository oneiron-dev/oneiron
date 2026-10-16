//! `/v1/owner/skills/judge`: the serve skill judge (OF-495). The owner reads
//! its typed-decision journal, records person-time on a run's receipt, and
//! measures an open skill edit on its goal's axes, live arms included.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::skill_optimize::{GoalAxisReport, measure_skill_edit_goal_axes};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::replay_judge::{self, JournalRow, ServeAxisBandit};
use crate::server::SyncServer;

/// Most journal rows one read returns.
const MAX_JOURNAL_ROWS: usize = 500;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/skills/judge/decisions", get(decisions))
        .route("/skills/judge/person-time", post(person_time))
        .route("/skills/judge/measure", post(measure))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalQuery {
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct Journal {
    revision: &'static str,
    decisions: Vec<JournalRow>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordPersonTime {
    /// The run's terminal receipt (`attempt:<32 hex>`).
    receipt: String,
    minutes: f64,
    /// What the person did: `review`, `answer`, `edit`, ...
    act: String,
}

#[derive(Debug, Serialize)]
struct PersonTimeTotal {
    receipt: String,
    minutes: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Measure {
    /// The open optimizer proposal, as 32 hex.
    proposal: String,
    /// Live pulls per online axis, across both arms.
    pulls_per_axis: u32,
}

/// `GET /v1/owner/skills/judge/decisions`: the newest journal rows.
async fn decisions(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<JournalQuery>, QueryRejection>,
) -> OwnerReply<Journal> {
    owner(&auth, &server)?;
    let limit = query_params(query)?
        .limit
        .unwrap_or(100)
        .clamp(1, MAX_JOURNAL_ROWS);
    let journal = blocking(move || -> OwnerResult<Journal> {
        Ok(Journal {
            revision: replay_judge::JUDGE_REVISION,
            decisions: replay_judge::journal(server.vault(), limit)?,
        })
    })
    .await?;
    Ok(Json(journal))
}

/// `POST /v1/owner/skills/judge/person-time`: one act's minutes on a run.
async fn person_time(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RecordPersonTime>, JsonRejection>,
) -> OwnerReply<PersonTimeTotal> {
    owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let total = blocking(move || -> OwnerResult<PersonTimeTotal> {
        let vault = server.vault();
        replay_judge::record_person_time(vault, &request.receipt, request.minutes, &request.act)
            .map_err(|error| OwnerError::Invalid(error.to_string()))?;
        Ok(PersonTimeTotal {
            minutes: replay_judge::person_minutes(vault, &request.receipt)?.unwrap_or(0.0),
            receipt: request.receipt,
        })
    })
    .await?;
    Ok(Json(total))
}

/// `POST /v1/owner/skills/judge/measure`: measures an open proposal on its
/// goal's plan with the registered judge and live arms, and keeps the report
/// for the gate.
async fn measure(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<Measure>, JsonRejection>,
) -> OwnerReply<GoalAxisReport> {
    owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let report = blocking(move || -> OwnerResult<GoalAxisReport> {
        let proposal = entity_id("proposal", &request.proposal)?;
        let judge = replay_judge::registered()
            .ok_or_else(|| OwnerError::Invalid("no skill judge is registered".to_owned()))?;
        let bandit = ServeAxisBandit::for_proposal(Arc::clone(server.vault()), &proposal)?;
        Ok(measure_skill_edit_goal_axes(
            server.vault(),
            &proposal,
            judge,
            &bandit,
            request.pulls_per_axis,
        )?)
    })
    .await?;
    Ok(Json(report))
}
