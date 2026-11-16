//! Full witnessed goal intake and explicit optimizer proposal/admission doors.
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::skill::SkillLifecycle;
use crate::skill_optimize::{self as optimize, GoalAxisBandit, HeldOutReplayNotes};
use crate::workspace_roster::{GoalInterviewTurns, GoalRecord};
use crate::{EntityId, Error, TimeRange, Vault};
use serde::{Deserialize, Serialize};

use super::{
    ProjectGoalDismissReceipt, ProjectGoalDismissRequest, ProjectGoalDismissTarget,
    SkillOptimizeResultRequest, SkillOptimizeResultView, skill_optimize_result_as_owner,
};

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

/// `vault.projects.goal.dismiss` on the caller's handle: a vault owner sets
/// aside a preference proposal or a full goal proposal; `false` when an
/// identical retry wrote nothing.
///
/// # Errors
///
/// FORBIDDEN for a caller that is not a recorded vault owner; a malformed
/// reference, a moved goal, a missing proposal, a blank or unbounded reason;
/// storage errors.
pub fn project_goal_dismiss(
    memory: &Memory<'_>,
    input: ProjectGoalDismissRequest,
) -> MemoryResult<ProjectGoalDismissReceipt> {
    let project = EntityId::from_hex(&input.project_ref)?;
    let dismissed = match input.target {
        ProjectGoalDismissTarget::Preference {
            expected_goal_ref,
            question_digest,
        } => memory.projects_goal_dismiss(
            project,
            EntityId::from_hex(&expected_goal_ref)?,
            &question_digest,
        )?,
        ProjectGoalDismissTarget::Proposal {
            proposal_ref,
            reason,
        } => memory.projects_goal_proposal_dismiss(
            project,
            EntityId::from_hex(&proposal_ref)?,
            &reason,
        )?,
    };
    Ok(ProjectGoalDismissReceipt { dismissed })
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

/// `vault.projects.goal.get` for the owner, under his proof.
pub fn project_goal_get_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    project: EntityId,
) -> MemoryResult<ProjectGoalView> {
    owner.revalidate(vault)?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    Ok(goal_view(
        project,
        vault.project_intake_goal_in_txn(&txn, project)?,
    ))
}

/// `vault.projects.goal.get` for the caller `memory` binds when it holds a
/// live Steward grant naming `read` (untangle 6.6d, F4), checked at this
/// read; a base agent reads through its own grant and scoped read.
///
/// # Errors
///
/// A caller who holds no such grant; storage errors.
pub fn project_goal_get_as_reader(
    memory: &crate::memory::Memory<'_>,
    project: EntityId,
) -> MemoryResult<ProjectGoalView> {
    let vault = memory.vault();
    let reader = crate::WriteActor::new(memory.actor(), memory.actor_class());
    crate::federation::admit_substrate_read_by(
        vault,
        reader,
        "vault.projects.goal.get",
        crate::federation::SubstrateRead::Goal,
    )?;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    Ok(goal_view(
        project,
        vault.project_intake_goal_as_in_txn(&txn, reader, project)?,
    ))
}

/// `vault.projects.goal.get` on a bound handle: the embedded owner reads
/// under its own proof, any other caller as a reader.
///
/// # Errors
///
/// As [`project_goal_get_as_owner`] and [`project_goal_get_as_reader`].
pub fn project_goal_get_embedded(
    memory: &crate::memory::Memory<'_>,
    project: EntityId,
) -> MemoryResult<ProjectGoalView> {
    match memory.embedded_owner("vault.projects.goal.get") {
        Ok(owner) => project_goal_get_as_owner(memory.vault(), &owner, project),
        Err(_) => project_goal_get_as_reader(memory, project),
    }
}

fn goal_view(project: EntityId, goal: Option<(EntityId, GoalRecord)>) -> ProjectGoalView {
    let (goal_claim, record) = match goal {
        Some((claim, record)) => (Some(claim), Some(record)),
        None => (None, None),
    };
    ProjectGoalView {
        project_ref: project,
        goal_claim,
        record,
    }
}

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::goal_optimize::{
    SkillOptimizeGoalBindRequest, SkillOptimizeGoalRequest, SkillOptimizeGoalRevision,
    SkillOptimizeGoalView, SkillOptimizeMeasureRequest, SkillOptimizeMeasurement,
    SkillOptimizePreferencesSetRequest, SkillOptimizeProposalReceipt, SkillOptimizeProposalRequest,
    SkillOptimizeProposeRequest, SkillOptimizeTradeoffPickRequest,
    SkillOptimizeTradeoffResolveRequest, TradeoffCapacityAdvisory,
};

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

pub fn skill_optimize_goal_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SkillOptimizeGoalRequest,
) -> MemoryResult<SkillOptimizeGoalView> {
    let goal = optimize::skill_edit_goal_as_owner(vault, owner, &input.skill)?;
    Ok(SkillOptimizeGoalView {
        goal_id: goal.goal_id,
        goal_revision: goal.revision,
        axes: goal.axes,
        project: goal.project.map(|(project, _)| project),
        goal_claim: goal.project.map(|(_, claim)| claim),
    })
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
