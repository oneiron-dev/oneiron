//! Live goal-axis measurement of a proposal (ARCH-0053: "Primary axes are
//! measured online." "Offline axes run on the held-out set first. Online axes
//! run through the bandit slice with a confidence bound.").
//!
//! [`measure_skill_edit_goal_axes`] runs [`measure_goal_axes`] over the plan
//! the skill's effective goal implies and keeps the report bound to the two
//! bodies, the reserved evidence and the plan it measured. For a goal joined
//! to a project's goal record, the gate takes each primary axis from that
//! report instead of the replay: an inconclusive interval is a tie on that
//! axis, never a gain, so overlapping bounds cannot reach admission. A report
//! that no longer binds the scored basis is no report at all.
use super::*;
use crate::error::ArtifactError;
use crate::skill_optimize::{
    GoalAxisBandit, GoalAxisPlan, GoalAxisReport, OnlineAxisOutcome, measure_goal_axes,
};
use serde::{Deserialize, Serialize};

const LIVE_PREFIX: &[u8] = b"skill_optimize/live_axes/v1\0";
const PLAN_DOMAIN: &[u8] = b"skill_optimize:live_axis_plan:v1\0";
const LABEL: &str = "skill live goal-axis row";
/// The mandatory cost axis the scorer reports in minutes on every case.
const HUMAN_MINUTES: &str = "human_minutes";

const fn retry(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::SkillEditGateRetry(reason))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveAxesRow {
    plan_digest: String,
    proposal_digest: String,
    target_digest: String,
    evidence_digest: String,
    report: GoalAxisReport,
}

fn key(proposal: &EntityId) -> Vec<u8> {
    [LIVE_PREFIX, proposal.as_bytes()].concat()
}

/// The plan a goal implies: primary axes online, floor and cost axes offline
/// on the held-out set. Human minutes are measured on every case anyway.
pub(super) fn goal_axis_plan(definition: &GoalDefinition, pulls_per_axis: u32) -> GoalAxisPlan {
    let mut plan = GoalAxisPlan {
        offline: Vec::new(),
        online: Vec::new(),
        pulls_per_axis,
    };
    for axis in &definition.axes {
        match axis.kind {
            GoalAxisKind::Primary => plan.online.push(axis.name.clone()),
            GoalAxisKind::Floor | GoalAxisKind::Cost if axis.name != HUMAN_MINUTES => {
                plan.offline.push(axis.name.clone());
            }
            GoalAxisKind::Floor | GoalAxisKind::Cost => {}
        }
    }
    plan
}

/// Which axes a plan measures where; the pull cap is a budget, not part of
/// what a report is about.
fn plan_digest(plan: &GoalAxisPlan) -> String {
    let mut hash = Sha256::new();
    hash.update(PLAN_DOMAIN);
    for (side, axes) in [
        (&b"offline"[..], &plan.offline),
        (&b"online"[..], &plan.online),
    ] {
        hash.update(side);
        hash.update(b"\0");
        for axis in axes {
            hash.update(axis.as_bytes());
            hash.update(b"\0");
        }
    }
    bytes_to_hex_lower(&hash.finalize())
}

/// The measurement plan of a skill's effective goal.
/// # Errors
/// An unreadable goal, or storage errors.
pub fn skill_goal_axis_plan(
    vault: &Vault,
    skill: &EntityId,
    pulls_per_axis: u32,
) -> Result<GoalAxisPlan> {
    let txn = vault.store.env.read_txn()?;
    Ok(goal_axis_plan(
        &goal_definition_in_txn(vault, &txn, skill)?,
        pulls_per_axis,
    ))
}

/// Measure an open proposal against the skill it revises on its goal's plan,
/// offline axes first, and keep the report for the gate. The live slice is
/// the caller's: `pulls_per_axis` caps each online axis across both arms.
/// # Errors
/// A proposal that is not an open optimizer proposal, an unreadable target or
/// goal, every [`measure_goal_axes`] error, and the retryable outcome when a
/// body, the reserved evidence or the plan moved while measuring.
pub fn measure_skill_edit_goal_axes(
    vault: &Vault,
    proposal: &EntityId,
    scorer: &dyn HeldOutReplayNotes,
    bandit: &dyn GoalAxisBandit,
    pulls_per_axis: u32,
) -> Result<GoalAxisReport> {
    let staged = vault
        .get_skill_record(proposal)?
        .ok_or(Error::EntityNotFound)?;
    require_open_optimizer_proposal(&staged)?;
    let target = target_of(&staged)?;
    let current = vault
        .get_skill_record(&target)?
        .ok_or(Error::EntityNotFound)?;
    let plan = skill_goal_axis_plan(vault, &target, pulls_per_axis)?;
    let report = measure_goal_axes(vault, target, &current, &staged, &plan, scorer, bandit)?;
    vault.with_write_txn_grouped(|txn| {
        let staged_now = vault.read_skill_record_in_txn(&*txn, proposal)?;
        let current_now = vault.read_skill_record_in_txn(&*txn, &target)?;
        let proposal_digest = skill_body_binding_digest(&staged_now)?;
        let target_digest = skill_body_binding_digest(&current_now)?;
        if proposal_digest != skill_body_binding_digest(&staged)?
            || target_digest != skill_body_binding_digest(&current)?
        {
            return Err(retry(
                "a skill body moved while its goal axes were measured",
            ));
        }
        let held_out = held_out_receipts_in_txn(vault, txn, &target)?;
        if held_out != report.held_out_receipts {
            return Err(retry(
                "the reserved evidence moved while the goal axes were measured",
            ));
        }
        if goal_axis_plan(
            &goal_definition_in_txn(vault, txn, &target)?,
            pulls_per_axis,
        ) != plan
        {
            return Err(retry("the goal moved while its axes were measured"));
        }
        let row = LiveAxesRow {
            plan_digest: plan_digest(&plan),
            proposal_digest,
            target_digest,
            evidence_digest: evidence_identity(&held_out).1,
            report: report.clone(),
        };
        let bytes = rmp_serde::to_vec_named(&row)
            .map_err(|_| invalid("live goal-axis row encoding failed"))?;
        vault.store.vault_meta.put(txn, &key(proposal), &bytes)?;
        Ok(())
    })?;
    Ok(report)
}

/// The live report kept for `proposal`, if one was measured.
/// # Errors
/// An unreadable row, or storage errors.
pub fn skill_edit_goal_axis_report(
    vault: &Vault,
    proposal: &EntityId,
) -> Result<Option<GoalAxisReport>> {
    let txn = vault.store.env.read_txn()?;
    Ok(load(vault, &txn, proposal)?.map(|row| row.report))
}

fn load(vault: &Vault, txn: &heed::RoTxn<'_>, proposal: &EntityId) -> Result<Option<LiveAxesRow>> {
    vault
        .store
        .vault_meta
        .get(txn, &key(proposal))?
        .map(|raw| rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex(LABEL)))
        .transpose()
}

/// Both bounds are validated into 0..=1, which an f32 holds.
#[allow(clippy::cast_possible_truncation)]
fn midpoint(bounds: crate::skill_optimize::ConfidenceInterval) -> f32 {
    f64::midpoint(bounds.lower, bounds.upper) as f32
}

/// The gate's vector for a project-bound goal: each online axis is taken from
/// the live report bound to this exact basis. Other goals keep the replay.
/// # Errors
/// The retryable outcome while no bound report exists, or a report naming an
/// axis the vector lacks.
pub(super) fn overlay_live_axes(
    vault: &Vault,
    proposal: &EntityId,
    basis: &ScoredBasis,
    definition: &GoalDefinition,
    mut axes: BTreeMap<String, GoalAxisScore>,
) -> Result<BTreeMap<String, GoalAxisScore>> {
    if definition.project.is_none() {
        return Ok(axes);
    }
    let plan = goal_axis_plan(definition, 0);
    if plan.online.is_empty() {
        return Ok(axes);
    }
    let txn = vault.store.env.read_txn()?;
    let row = load(vault, &txn, proposal)?;
    drop(txn);
    let row = row
        .filter(|row| {
            row.plan_digest == plan_digest(&plan)
                && row.proposal_digest == basis.proposal_digest
                && row.target_digest == basis.target_digest
                && row.evidence_digest == basis.evidence_digest
        })
        .ok_or(retry(
            "a project goal's primary axes need a live measurement of this proposal first",
        ))?;
    for measured in &row.report.online {
        let axis = axes
            .get_mut(&measured.axis)
            .ok_or(Error::CorruptedIndex(LABEL))?;
        let before = midpoint(measured.before);
        axis.before = before;
        axis.after = match measured.outcome {
            OnlineAxisOutcome::Inconclusive => before,
            OnlineAxisOutcome::CandidateBetter | OnlineAxisOutcome::IncumbentBetter => {
                midpoint(measured.after)
            }
        };
    }
    Ok(axes)
}
