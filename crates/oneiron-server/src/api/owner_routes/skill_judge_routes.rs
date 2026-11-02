//! `/v1/owner/skills/judge`: the serve skill judge (OF-495). The owner reads
//! its typed-decision journal, records person-time on a run's receipt, and
//! measures an open skill edit on its goal's axes, live arms included.
//!
//! The judge swaps (OF-184): the owner reads the shadow passes and the
//! incumbent, sets the swap policy, and hand-tests a swap by picking the
//! judge whose answer is right on a case the two judges disagreed on. A
//! blind preference case settles on the owner's pick between its pair's two
//! responses (`/skills/judge/pairs`).
//!
//! The goal joins and the learned picks: the owner joins a skill's goal to a
//! project's goal record, reads the preferences its picks taught, answers the
//! tradeoff asks that have climbed to them, and reads the preferences the
//! loop proposes for a project's goal. A proposal never revises the goal;
//! only the project's goal interview does.

use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::skill_optimize::{
    GoalAxisReport, HeldOutReplayNotes, JudgeIncumbent, JudgeSwapPick, JudgeSwapPolicy,
    JudgeSwapReceipt, PreferredResponse, ProjectGoalRevisionProposal, ResponsePairPick,
    SkillTradeoffAsk, SkillTradeoffPreferences, TradeoffChoice, judge_incumbent, judge_swap_policy,
    judge_swap_receipts, measure_skill_edit_goal_axes, pick_judge_swap_case, pick_response_pair,
    project_goal_revision_proposals, response_pair_picks, set_judge_swap_policy,
    set_skill_goal_project, settle_skill_tradeoff_ask, skill_goal_project, skill_tradeoff_asks_for,
    skill_tradeoff_preferences,
};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::replay_judge::{self, JournalRow, ServeAxisBandit};
use crate::server::SyncServer;

mod tradeoff_resolve;
pub(crate) use self::tradeoff_resolve::tradeoff_resolve_body_schema;

/// Most journal rows one read returns.
const MAX_JOURNAL_ROWS: usize = 500;

pub(super) fn owner_table() -> OwnerTable {
    let mut table = vec![
        (
            OwnerRoute {
                method: "get",
                path: "/skills/judge/decisions",
                summary: "The newest journal rows.",
                row: None,
            },
            get(decisions),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/skills/judge/person-time",
                summary: "One act's minutes on a run.",
                row: None,
            },
            post(person_time),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/skills/judge/measure",
                summary: "Measures an open proposal on its goal's plan with the registered judge and live arms, and keeps the report for the gate.",
                row: None,
            },
            post(measure),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/skills/judge/goal-project",
                summary: "The project a skill's goal is joined to.",
                row: None,
            },
            get(goal_project),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/skills/judge/goal-project",
                summary: "Joins a skill's goal to a project's goal record, or unbinds it.",
                row: None,
            },
            post(bind_goal_project),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/skills/judge/preferences",
                summary: "The tradeoff rules of a skill's goal, the ones its responsible person's picks taught included.",
                row: None,
            },
            get(preferences),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/skills/judge/tradeoff-asks",
                summary: "The tradeoff asks that have climbed to a role the owner holds.",
                row: None,
            },
            get(tradeoff_asks),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/skills/judge/tradeoff-asks/pick",
                summary: "The owner's A/B pick.",
                row: None,
            },
            post(pick),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/skills/judge/goal-revisions",
                summary: "The preferences the loop proposes for the project's goal in force, oldest first, for its goal interview to show.",
                row: None,
            },
            get(goal_revisions),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/skills/judge/swaps",
                summary: "The incumbent judge, the swap policy and every swap receipt, each disagreement's ruling included.",
                row: None,
            },
            get(swaps),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/skills/judge/swaps/pick",
                summary: "The owner's hand-test pick on one disagreement.",
                row: None,
            },
            post(swap_pick),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/skills/judge/pairs",
                summary: "Every pick the owner made between a blind preference pair's two responses.",
                row: None,
            },
            get(pair_picks),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/skills/judge/pairs/pick",
                summary: "The owner's pick between a blind preference pair's two responses.",
                row: None,
            },
            post(pair_pick),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/skills/judge/swap-policy",
                summary: "The tie-breakers, the pinned divergence rate and the hands-on setting in force.",
                row: None,
            },
            get(swap_policy),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/skills/judge/swap-policy",
                summary: "Replaces the swap policy; a field left out takes its default.",
                row: None,
            },
            post(set_swap_policy),
        ),
    ];
    table.extend(tradeoff_resolve::owner_table());
    table
}

/// The OpenAPI schema of `POST /v1/owner/skills/judge/goal-project`'s body (FIX 11611):
/// [`BindGoalProject`].
pub(crate) fn bind_goal_project_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<BindGoalProject>()
}

/// The OpenAPI schema of `POST /v1/owner/skills/judge/goal-project`'s answer (FIX 11611):
/// [`GoalRevision`].
pub(crate) fn goal_revision_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<GoalRevision>()
}

/// The OpenAPI schema of `POST /v1/owner/skills/judge/measure`'s body (FIX 11611): [`Measure`].
pub(crate) fn measure_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<Measure>()
}

/// The OpenAPI schema of `POST /v1/owner/skills/judge/measure`'s answer (FIX 11611):
/// [`GoalAxisReport`].
pub(crate) fn goal_axis_report_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<GoalAxisReport>()
}

/// The OpenAPI schema of `POST /v1/owner/skills/judge/pairs/pick`'s body (FIX 11611): [`PairPick`].
pub(crate) fn pair_pick_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PairPick>()
}

/// The OpenAPI schema of `POST /v1/owner/skills/judge/pairs/pick`'s answer (FIX 11611):
/// [`ResponsePairPick`].
pub(crate) fn response_pair_pick_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ResponsePairPick>()
}

/// The OpenAPI schema of `POST /v1/owner/skills/judge/person-time`'s body (FIX 11611):
/// [`RecordPersonTime`].
pub(crate) fn record_person_time_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RecordPersonTime>()
}

/// The OpenAPI schema of `POST /v1/owner/skills/judge/person-time`'s answer (FIX 11611):
/// [`PersonTimeTotal`].
pub(crate) fn person_time_total_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PersonTimeTotal>()
}

/// The OpenAPI schema of `POST /v1/owner/skills/judge/swap-policy`'s body and answer (FIX 11611):
/// [`JudgeSwapPolicy`].
pub(crate) fn judge_swap_policy_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<JudgeSwapPolicy>()
}

/// The OpenAPI schema of `POST /v1/owner/skills/judge/swaps/pick`'s body (FIX 11611): [`SwapPick`].
pub(crate) fn swap_pick_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SwapPick>()
}

/// The OpenAPI schema of `POST /v1/owner/skills/judge/swaps/pick`'s answer (FIX 11611):
/// [`JudgeSwapPick`].
pub(crate) fn judge_swap_pick_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<JudgeSwapPick>()
}

/// The OpenAPI schema of `POST /v1/owner/skills/judge/tradeoff-asks/pick`'s body (FIX 11611):
/// [`Pick`].
pub(crate) fn tradeoff_pick_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<Pick>()
}

/// The OpenAPI schema of `POST /v1/owner/skills/judge/tradeoff-asks/pick`'s answer (FIX 11611):
/// [`Settled`].
pub(crate) fn tradeoff_settled_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<Settled>()
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct PairPick {
    /// The blind preference pair, `first|second` (the two receipts).
    pair_ref: String,
    /// The better response: `first` or `second`.
    preferred: PreferredResponse,
}

#[derive(Debug, Serialize)]
struct Swaps {
    /// The judge the kept history reads on; `None` before the first pass.
    incumbent: Option<JudgeIncumbent>,
    policy: JudgeSwapPolicy,
    /// Every shadow pass and re-pin, oldest first.
    receipts: Vec<JudgeSwapReceipt>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct SwapPick {
    /// The swap receipt, as 32 hex.
    receipt: String,
    /// The disagreement's case.
    case_ref: String,
    /// The judge whose answer is right, `model@version`.
    judge: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillQuery {
    /// The active skill, as 32 hex.
    skill: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectQuery {
    /// The project, as 32 hex.
    project: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct BindGoalProject {
    skill: String,
    /// The project whose goal record the skill's goal joins; absent unbinds.
    #[serde(default)]
    project: Option<String>,
}

#[derive(Debug, Serialize)]
struct GoalProject {
    skill: String,
    project: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct GoalRevision {
    /// The goal revision the join minted: every pending ask and standing
    /// acceptance is re-ruled under it.
    goal_revision: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct Pick {
    /// The open optimizer proposal the ask is about, as 32 hex.
    proposal: String,
    /// The digest of the exact question the pick answers.
    question_digest: String,
    choice: TradeoffChoice,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct Settled {
    proposal: String,
    accepted: bool,
    goal_revision: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalQuery {
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct Journal {
    /// The registered judge's `judge_revision()`; `None` when no judge is
    /// registered, with every stored row still returned.
    revision: Option<String>,
    decisions: Vec<JournalRow>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct RecordPersonTime {
    /// The run's terminal receipt (`attempt:<32 hex>`).
    receipt: String,
    minutes: f64,
    /// What the person did: `review`, `answer`, `edit`, ...
    act: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct PersonTimeTotal {
    receipt: String,
    minutes: f64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct Measure {
    /// The open optimizer proposal, as 32 hex.
    proposal: String,
    /// Live pulls per online axis, across both arms; `[skills]
    /// live_pulls_per_axis` when absent.
    pulls_per_axis: Option<u32>,
}

/// `GET /v1/owner/skills/judge/decisions`: the newest journal rows, with
/// the registered judge's revision; `None` when no judge is registered,
/// with every stored row still returned.
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
            revision: replay_judge::registered().map(|judge| judge.judge_revision().to_owned()),
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
    payload: OwnerJsonBody<RecordPersonTime>,
) -> OwnerReply<PersonTimeTotal> {
    owner(&auth, &server)?;
    let request = payload.read(&server).await?;
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
    payload: OwnerJsonBody<Measure>,
) -> OwnerReply<GoalAxisReport> {
    owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let report = blocking(move || -> OwnerResult<GoalAxisReport> {
        let proposal = entity_id("proposal", &request.proposal)?;
        let judge = replay_judge::registered()
            .ok_or_else(|| OwnerError::Invalid("no skill judge is registered".to_owned()))?;
        let pulls_per_axis = request
            .pulls_per_axis
            .or(judge.live_pulls_per_axis())
            .ok_or_else(|| {
                OwnerError::Invalid(
                    "name pulls_per_axis, or set [skills] live_pulls_per_axis".to_owned(),
                )
            })?;
        let bandit = ServeAxisBandit::for_proposal(judge, &proposal)?;
        Ok(measure_skill_edit_goal_axes(
            server.vault(),
            &proposal,
            judge,
            &bandit,
            pulls_per_axis,
        )?)
    })
    .await?;
    Ok(Json(report))
}

/// `GET /v1/owner/skills/judge/goal-project?skill=`: the project a skill's
/// goal is joined to.
async fn goal_project(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<SkillQuery>, QueryRejection>,
) -> OwnerReply<GoalProject> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let joined = blocking(move || -> OwnerResult<GoalProject> {
        let skill = entity_id("skill", &query.skill)?;
        Ok(GoalProject {
            project: skill_goal_project(server.vault(), &skill)?.map(|id| id.to_hex()),
            skill: query.skill,
        })
    })
    .await?;
    Ok(Json(joined))
}

/// `POST /v1/owner/skills/judge/goal-project`: joins a skill's goal to a
/// project's goal record, or unbinds it.
async fn bind_goal_project(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<BindGoalProject>,
) -> OwnerReply<GoalRevision> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let revision = blocking(move || -> OwnerResult<GoalRevision> {
        let skill = entity_id("skill", &request.skill)?;
        let project = request
            .project
            .as_deref()
            .map(|project| entity_id("project", project))
            .transpose()?;
        Ok(GoalRevision {
            goal_revision: set_skill_goal_project(server.vault(), &owner, &skill, project)?,
        })
    })
    .await?;
    Ok(Json(revision))
}

/// `GET /v1/owner/skills/judge/preferences?skill=`: the tradeoff rules of a
/// skill's goal, the ones its responsible person's picks taught included.
async fn preferences(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<SkillQuery>, QueryRejection>,
) -> OwnerReply<Option<SkillTradeoffPreferences>> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let preferences = blocking(move || -> OwnerResult<Option<SkillTradeoffPreferences>> {
        let skill = entity_id("skill", &query.skill)?;
        Ok(skill_tradeoff_preferences(server.vault(), &skill)?)
    })
    .await?;
    Ok(Json(preferences))
}

/// `GET /v1/owner/skills/judge/tradeoff-asks`: the tradeoff asks that have
/// climbed to a role the owner holds.
async fn tradeoff_asks(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<SkillTradeoffAsk>> {
    let owner = owner(&auth, &server)?;
    let asks = blocking(move || -> OwnerResult<Vec<SkillTradeoffAsk>> {
        let person = owner.actor_for_read(server.vault())?;
        Ok(skill_tradeoff_asks_for(server.vault(), &person)?)
    })
    .await?;
    Ok(Json(asks))
}

/// `POST /v1/owner/skills/judge/tradeoff-asks/pick`: the owner's A/B pick.
/// It settles the pending tradeoff, is learned as the goal's preference for
/// that axis signature and, for a project-bound goal, is proposed for the
/// project's goal record.
async fn pick(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<Pick>,
) -> OwnerReply<Settled> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let settled = blocking(move || -> OwnerResult<Settled> {
        let proposal = entity_id("proposal", &request.proposal)?;
        let verdict = settle_skill_tradeoff_ask(
            server.vault(),
            &owner,
            &proposal,
            &request.question_digest,
            request.choice,
            unix_seconds(),
        )?;
        Ok(Settled {
            proposal: request.proposal,
            accepted: verdict.accepted,
            goal_revision: verdict.goal_revision,
        })
    })
    .await?;
    Ok(Json(settled))
}

/// `GET /v1/owner/skills/judge/goal-revisions?project=`: the preferences the
/// loop proposes for the project's goal in force, oldest first, for its goal
/// interview to show.
async fn goal_revisions(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<ProjectQuery>, QueryRejection>,
) -> OwnerReply<Vec<ProjectGoalRevisionProposal>> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let proposals = blocking(move || -> OwnerResult<Vec<ProjectGoalRevisionProposal>> {
        let project = entity_id("project", &query.project)?;
        Ok(project_goal_revision_proposals(server.vault(), project)?)
    })
    .await?;
    Ok(Json(proposals))
}

/// `GET /v1/owner/skills/judge/swaps`: the incumbent judge, the swap
/// policy and every swap receipt, each disagreement's ruling included.
async fn swaps(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Swaps> {
    owner(&auth, &server)?;
    let swaps = blocking(move || -> OwnerResult<Swaps> {
        let vault = server.vault();
        Ok(Swaps {
            incumbent: judge_incumbent(vault)?,
            policy: judge_swap_policy(vault)?,
            receipts: judge_swap_receipts(vault)?,
        })
    })
    .await?;
    Ok(Json(swaps))
}

/// `POST /v1/owner/skills/judge/swaps/pick`: the owner's hand-test pick on
/// one disagreement. It decides that case in every later pass between the
/// two judges, and can re-pin a takeover it contradicts. On a skill's case it
/// is a label in the skill's judge anchor; either way it is final.
async fn swap_pick(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<SwapPick>,
) -> OwnerReply<JudgeSwapPick> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let pick = blocking(move || -> OwnerResult<JudgeSwapPick> {
        Ok(pick_judge_swap_case(
            server.vault(),
            &owner,
            &request.receipt,
            &request.case_ref,
            &request.judge,
            unix_seconds(),
        )?)
    })
    .await?;
    Ok(Json(pick))
}

/// `GET /v1/owner/skills/judge/pairs`: every pick the owner made between a
/// blind preference pair's two responses.
async fn pair_picks(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<ResponsePairPick>> {
    owner(&auth, &server)?;
    let picks = blocking(move || -> OwnerResult<Vec<ResponsePairPick>> {
        Ok(response_pair_picks(server.vault())?)
    })
    .await?;
    Ok(Json(picks))
}

/// `POST /v1/owner/skills/judge/pairs/pick`: the owner's pick between a
/// blind preference pair's two responses. It settles every judge-swap
/// disagreement asked about that pair; it is final.
async fn pair_pick(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<PairPick>,
) -> OwnerReply<ResponsePairPick> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let pick = blocking(move || -> OwnerResult<ResponsePairPick> {
        Ok(pick_response_pair(
            server.vault(),
            &owner,
            &request.pair_ref,
            request.preferred,
            unix_seconds(),
        )?)
    })
    .await?;
    Ok(Json(pick))
}

/// `GET /v1/owner/skills/judge/swap-policy`: the tie-breakers, the pinned
/// divergence rate and the hands-on setting in force.
async fn swap_policy(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<JudgeSwapPolicy> {
    owner(&auth, &server)?;
    let policy = blocking(move || -> OwnerResult<JudgeSwapPolicy> {
        Ok(judge_swap_policy(server.vault())?)
    })
    .await?;
    Ok(Json(policy))
}

/// `POST /v1/owner/skills/judge/swap-policy`: replaces the swap policy; a
/// field left out takes its default.
async fn set_swap_policy(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<JudgeSwapPolicy>,
) -> OwnerReply<JudgeSwapPolicy> {
    let owner = owner(&auth, &server)?;
    let policy = payload.read(&server).await?;
    let policy = blocking(move || -> OwnerResult<JudgeSwapPolicy> {
        set_judge_swap_policy(server.vault(), &owner, &policy)?;
        Ok(policy)
    })
    .await?;
    Ok(Json(policy))
}

/// Unix seconds now, the time a pick is learned at.
fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
