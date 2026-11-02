//! Full witnessed goal intake and explicit optimizer proposal/admission doors.
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};
use crate::skill::SkillLifecycle;
use crate::skill_optimize::{self as optimize, GoalAxisBandit, GoalAxisReport, HeldOutReplayNotes};
use crate::workspace_roster::{GoalInterviewTurns, GoalRecord};
use crate::{EntityId, Error, TimeRange, Vault};
use serde::{Deserialize, Serialize};

use super::{SkillOptimizeResultRequest, SkillOptimizeResultView, skill_optimize_result_as_owner};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalIntakeCompleteRequest {
    pub project_ref: EntityId,
    pub attempt_ref: EntityId,
    pub turns: GoalInterviewTurns,
    /// Must equal the witnessed human answer and the confirmed agent draft.
    pub record: GoalRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProjectGoalIntakeReceipt {
    pub project_ref: EntityId,
    pub goal_claim: EntityId,
    pub record: GoalRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProjectGoalView {
    pub project_ref: EntityId,
    pub goal_claim: Option<EntityId>,
    pub record: Option<GoalRecord>,
}

pub fn project_goal_intake_complete_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &ProjectGoalIntakeCompleteRequest,
) -> MemoryResult<ProjectGoalIntakeReceipt> {
    let claim = vault.complete_project_goal_intake(
        owner,
        input.project_ref,
        attempt(input.attempt_ref)?,
        input.turns,
        Some(&input.record),
        vault.now_recorded_at(),
    )?;
    Ok(ProjectGoalIntakeReceipt {
        project_ref: input.project_ref,
        goal_claim: claim,
        record: input.record.clone(),
    })
}

pub fn project_goal_get_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    project: EntityId,
) -> MemoryResult<ProjectGoalView> {
    owner.revalidate(vault)?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let (goal_claim, record) = match vault.project_intake_goal_in_txn(&txn, project)? {
        Some((claim, record)) => (Some(claim), Some(record)),
        None => (None, None),
    };
    Ok(ProjectGoalView {
        project_ref: project,
        goal_claim,
        record,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizeProposeRequest {
    pub skill: EntityId,
    pub expected_version: String,
    /// A real skill_optimize queue attempt; never a caller-chosen cycle label.
    pub attempt_ref: EntityId,
    pub desc: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillOptimizeProposalReceipt {
    pub skill: EntityId,
    pub proposal: EntityId,
}

pub fn skill_optimize_propose_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillOptimizeProposeRequest,
) -> MemoryResult<SkillOptimizeProposalReceipt> {
    let proposal = optimize::propose_skill_edit_as_owner(
        vault,
        owner,
        attempt(input.attempt_ref)?,
        &input.skill,
        &input.expected_version,
        &input.desc,
        &input.rationale,
    )?;
    Ok(SkillOptimizeProposalReceipt {
        skill: input.skill,
        proposal,
    })
}

fn attempt(id: EntityId) -> MemoryResult<crate::attempt_queue::AttemptId> {
    crate::attempt_queue::AttemptId::from_bytes(id.as_bytes())
        .map_err(|_| MemoryError::bad_request("invalid attempt_ref"))
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizeProposalRequest {
    pub proposal: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizeMeasureRequest {
    pub proposal: EntityId,
    #[serde(default)]
    pub pulls_per_axis: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillOptimizeMeasurement {
    pub preflight: optimize::SkillEditPreflight,
    /// Absent on a failed floor: no online pull is spent.
    pub report: Option<GoalAxisReport>,
}

pub fn skill_optimize_measure_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillOptimizeMeasureRequest,
    scorer: &dyn HeldOutReplayNotes,
    bandit: &dyn GoalAxisBandit,
    pulls_per_axis: u32,
) -> MemoryResult<SkillOptimizeMeasurement> {
    let preflight = optimize::preflight_skill_edit_offline_floors_as_owner(
        vault,
        owner,
        &input.proposal,
        scorer,
    )?;
    let report = if preflight.passed {
        Some(optimize::measure_skill_edit_goal_axes_as_owner(
            vault,
            owner,
            &input.proposal,
            scorer,
            bandit,
            pulls_per_axis,
        )?)
    } else {
        None
    };
    Ok(SkillOptimizeMeasurement { preflight, report })
}

pub fn skill_optimize_score_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillOptimizeProposalRequest,
    scorer: &dyn HeldOutReplayNotes,
) -> MemoryResult<SkillOptimizeResultView> {
    optimize::score_gate_skill_edit_as_owner(vault, owner, &input.proposal, scorer)?;
    result(vault, owner, input.proposal)
}

/// Activate only a standing gate acceptance, and freeze its predecessor in
/// the same transaction. A refusal commits its normal verdict, never a flip.
pub fn skill_optimize_admit_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillOptimizeProposalRequest,
) -> MemoryResult<SkillOptimizeResultView> {
    let now = vault.now_recorded_at();
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        let verdict = optimize::skill_edit_verdict_in_txn(vault, txn, &input.proposal)?
            .ok_or_else(|| Error::InvalidConfig("no standing optimizer verdict".to_owned()))?;
        let proposed = vault.read_skill_record_in_txn(txn, &input.proposal)?;
        let incumbent = vault.read_skill_record_in_txn(txn, &verdict.skill)?;
        // Exact redelivery after the atomic activation/supersession.
        if verdict.accepted
            && proposed.lifecycle_status == SkillLifecycle::Active
            && incumbent.lifecycle_status == SkillLifecycle::Superseded
            && optimize::skill_body_binding_digest(&proposed)? == verdict.proposal_digest
            && optimize::skill_body_binding_digest(&incumbent)? == verdict.target_digest
        {
            return Ok(());
        }
        if vault
            .admit_optimized_skill_in_txn(txn, &input.proposal, occurred, now)?
            .is_none()
        {
            vault.supersede_skill_record_in_txn(
                txn,
                &verdict.skill,
                &input.proposal,
                occurred,
                now,
            )?;
        }
        Ok(())
    })?;
    result(vault, owner, input.proposal)
}

fn result(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    proposal: EntityId,
) -> MemoryResult<SkillOptimizeResultView> {
    skill_optimize_result_as_owner(
        vault,
        owner,
        &SkillOptimizeResultRequest {
            job_ref: None,
            proposal: Some(proposal),
        },
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizeGoalRequest {
    pub skill: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillOptimizeGoalView {
    pub goal_id: EntityId,
    pub goal_revision: String,
    pub axes: Vec<optimize::GoalAxisSpec>,
    pub project: Option<EntityId>,
    pub goal_claim: Option<EntityId>,
}

pub fn skill_optimize_goal_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillOptimizeGoalRequest,
) -> MemoryResult<SkillOptimizeGoalView> {
    owner.revalidate(vault)?;
    let goal = optimize::skill_edit_goal(vault, &input.skill)?;
    Ok(SkillOptimizeGoalView {
        goal_id: goal.goal_id,
        goal_revision: goal.revision,
        axes: goal.axes,
        project: goal.project.map(|(project, _)| project),
        goal_claim: goal.project.map(|(_, claim)| claim),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizeGoalBindRequest {
    pub skill: EntityId,
    /// None unbinds; it never edits the project's goal record.
    pub project: Option<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillOptimizeGoalRevision {
    pub goal_revision: String,
    /// The tradeoff capacity crossings the goal's rules stand over now, if
    /// any; set only by the preference write, never by the goal bind.
    pub tradeoff_capacity_advisory: Option<Vec<TradeoffCapacityAdvisory>>,
}

/// One policy limit a goal's tradeoff rules have crossed (FIX 9123): the
/// capacity advisory the gate logs, carried on the preference write
/// response and the ask view. Advisory only: nothing was refused, and
/// every pending decision keeps its durable ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TradeoffCapacityAdvisory {
    /// More authored rules than `max_authored_rules`.
    AuthoredRules { held: u64, limit: u64 },
    /// More learned picks than a finite `max_learned_rules`.
    LearnedRules { held: u64, limit: u64 },
}

impl TradeoffCapacityAdvisory {
    /// The reason code the gate logs for this crossing.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::AuthoredRules { .. } => "gate.tradeoff_authored_rules_over_policy",
            Self::LearnedRules { .. } => "gate.tradeoff_learned_rules_over_policy",
        }
    }
}

/// The capacity crossings `preferences` stands over now, against its
/// holder's resolved limits: the advisory the gate logs, recomputed here
/// for the DTO without touching the gate. Empty when the rules fit, and
/// when the policy cannot be read: an unreadable policy skips the
/// advisory, never the read or write it rides on.
fn tradeoff_capacity_advisory(
    vault: &Vault,
    preferences: &optimize::SkillTradeoffPreferences,
) -> Vec<TradeoffCapacityAdvisory> {
    let txn = match vault.store.env.read_txn() {
        Ok(txn) => txn,
        Err(_) => return Vec::new(),
    };
    let limits = match crate::gate::skill_tradeoff_limits_in_txn(
        &vault.store,
        &txn,
        &preferences.responsible,
    ) {
        Ok(limits) => limits,
        Err(_) => return Vec::new(),
    };
    let count = |rules: &[optimize::TradeoffRule]| u64::try_from(rules.len()).unwrap_or(u64::MAX);
    let mut crossings = Vec::new();
    if count(&preferences.rules) > limits.max_authored_rules {
        crossings.push(TradeoffCapacityAdvisory::AuthoredRules {
            held: count(&preferences.rules),
            limit: limits.max_authored_rules,
        });
    }
    if let Some(limit) = limits.max_learned_rules
        && count(&preferences.learned) > limit
    {
        crossings.push(TradeoffCapacityAdvisory::LearnedRules {
            held: count(&preferences.learned),
            limit,
        });
    }
    crossings
}

pub fn skill_optimize_goal_bind_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillOptimizeGoalBindRequest,
) -> MemoryResult<SkillOptimizeGoalRevision> {
    Ok(SkillOptimizeGoalRevision {
        goal_revision: optimize::set_skill_goal_project(vault, owner, &input.skill, input.project)?,
        tradeoff_capacity_advisory: None,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizePreferencesSetRequest {
    pub skill: EntityId,
    pub rules: Vec<optimize::TradeoffRule>,
    pub jev_band: Option<crate::llm::decision::DecisionBand>,
}

pub fn skill_optimize_preferences_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillOptimizeGoalRequest,
) -> MemoryResult<Option<optimize::SkillTradeoffPreferences>> {
    owner.revalidate(vault)?;
    Ok(optimize::skill_tradeoff_preferences(vault, &input.skill)?)
}

pub fn skill_optimize_preferences_set_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillOptimizePreferencesSetRequest,
) -> MemoryResult<SkillOptimizeGoalRevision> {
    let goal_revision = optimize::set_skill_tradeoff_preferences(
        vault,
        owner,
        &input.skill,
        input.rules.clone(),
        input.jev_band,
    )?;
    let tradeoff_capacity_advisory = optimize::skill_tradeoff_preferences(vault, &input.skill)
        .ok()
        .flatten()
        .map(|preferences| tradeoff_capacity_advisory(vault, &preferences))
        .filter(|crossings| !crossings.is_empty());
    Ok(SkillOptimizeGoalRevision {
        goal_revision,
        tradeoff_capacity_advisory,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillOptimizeTradeoffAskView {
    /// The engine-computed digest the pick must echo; no client codec is needed.
    pub question_digest: String,
    pub ask: optimize::SkillTradeoffAsk,
    /// The tradeoff capacity crossings the ask's goal rules stand over now,
    /// if any; an advisory, never a refusal.
    pub tradeoff_capacity_advisory: Option<Vec<TradeoffCapacityAdvisory>>,
}

/// One ask with its question digest and its goal's capacity advisory. The
/// advisory reads the goal's preferences now, through the standing verdict
/// on the ask's proposal; an ask no verdict or preference row answers
/// carries none.
fn tradeoff_ask_view(
    vault: &Vault,
    ask: optimize::SkillTradeoffAsk,
) -> MemoryResult<SkillOptimizeTradeoffAskView> {
    let question_digest = ask.question.digest()?;
    let tradeoff_capacity_advisory = optimize::skill_edit_verdict(vault, &ask.question.proposal)
        .ok()
        .flatten()
        .and_then(|verdict| {
            optimize::skill_tradeoff_preferences(vault, &verdict.skill)
                .ok()
                .flatten()
        })
        .map(|preferences| tradeoff_capacity_advisory(vault, &preferences))
        .filter(|crossings| !crossings.is_empty());
    Ok(SkillOptimizeTradeoffAskView {
        question_digest,
        ask,
        tradeoff_capacity_advisory,
    })
}

pub fn skill_optimize_tradeoff_asks_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> MemoryResult<Vec<SkillOptimizeTradeoffAskView>> {
    let actor = owner.actor_for_read(vault)?;
    optimize::skill_tradeoff_asks_for(vault, &actor)?
        .into_iter()
        .map(|ask| tradeoff_ask_view(vault, ask))
        .collect()
}

/// [`skill_optimize_tradeoff_asks_as_owner`] for any person or agent (FIX
/// 8178): the asks that have climbed to a responsible role `actor` holds,
/// as `GET /v1/core/skills/tradeoff-asks` lists them. The reached-role check
/// is the authorization.
pub fn skill_optimize_tradeoff_asks_for(
    vault: &Vault,
    actor: &EntityId,
) -> MemoryResult<Vec<SkillOptimizeTradeoffAskView>> {
    optimize::skill_tradeoff_asks_for(vault, actor)?
        .into_iter()
        .map(|ask| tradeoff_ask_view(vault, ask))
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizeTradeoffPickRequest {
    pub proposal: EntityId,
    pub question_digest: String,
    /// Both approve and reject learn the responsible person's preference.
    pub choice: optimize::TradeoffChoice,
}

pub fn skill_optimize_tradeoff_pick_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillOptimizeTradeoffPickRequest,
) -> MemoryResult<SkillOptimizeResultView> {
    optimize::settle_skill_tradeoff_ask(
        vault,
        owner,
        &input.proposal,
        &input.question_digest,
        input.choice,
        vault.now_recorded_at(),
    )?;
    result(vault, owner, input.proposal)
}

/// [`skill_optimize_tradeoff_pick_as_owner`] for a person or agent holding
/// the role the ask reached (FIX 8178), settled as `by` exactly as
/// `POST /v1/core/skills/tradeoff-asks/pick` settles it. It answers what the
/// pick settled: its verdict, proposal and skill. The owner's whole result
/// read (lifecycles, governance, every verdict) stays the owner's.
pub fn skill_optimize_tradeoff_pick_by(
    vault: &Vault,
    by: &crate::WriteActor,
    input: &SkillOptimizeTradeoffPickRequest,
) -> MemoryResult<SkillOptimizeResultView> {
    let verdict = optimize::settle_skill_tradeoff_ask_as(
        vault,
        by,
        &input.proposal,
        &input.question_digest,
        input.choice,
        vault.now_recorded_at(),
    )?;
    let view = super::skills::verdict_view(verdict);
    Ok(SkillOptimizeResultView {
        job_ref: None,
        state: None,
        kind: None,
        last_error: None,
        skill: Some(view.skill),
        proposal: Some(view.proposal),
        proposal_lifecycle: None,
        incumbent_lifecycle: None,
        governance: None,
        verdict: Some(view.clone()),
        verdicts: vec![view],
    })
}

/// The owner's decision on one exact pending tradeoff (FIX 9125): the
/// proposal, the pending verdict the ask names, the bounded decision
/// evidence reference, and approve or reject.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillOptimizeTradeoffResolveRequest {
    pub proposal: EntityId,
    pub pending: EntityId,
    pub evidence: String,
    pub choice: optimize::TradeoffChoice,
}

/// Applies the owner's tradeoff decision: an approval writes an
/// accepted-tradeoff permission (or a deferred row the next scored cycle
/// admits through), a rejection writes the refusal. It learns no
/// preference; an A/B pick does. Only the owner resolves; agents answer
/// asks through [`skill_optimize_tradeoff_pick_by`].
pub fn skill_optimize_tradeoff_resolve_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillOptimizeTradeoffResolveRequest,
) -> MemoryResult<SkillOptimizeResultView> {
    optimize::resolve_skill_edit_tradeoff(
        vault,
        &input.proposal,
        input.pending,
        owner,
        &input.evidence,
        input.choice,
        vault.now_recorded_at(),
    )?;
    result(vault, owner, input.proposal)
}
