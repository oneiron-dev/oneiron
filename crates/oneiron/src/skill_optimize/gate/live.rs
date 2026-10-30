//! Live goal-axis measurement of a proposal (ARCH-0053: "Primary axes are
//! measured online." "Offline axes run on the held-out set first. Online axes
//! run through the bandit slice with a confidence bound.").
//!
//! [`measure_skill_edit_goal_axes`] runs [`measure_goal_axes`] over the plan
//! the skill's effective goal implies and keeps the report bound to the two
//! bodies, the reserved evidence and the plan it measured. For a goal joined
//! to a project's goal record, the gate takes every axis that report measured
//! instead of judging it again: each primary axis from its online interval,
//! each offline floor and cost from the held-out pass, and human minutes from
//! the live runs' person-time. An inconclusive interval stays unknown (FIX
//! 8845, OF-495): the gate defers any admission it would let through, and the
//! next pass measures the proposal again. A report that no longer binds the
//! scored basis, or the judge and rubric scoring now, is no report at all.
use super::*;
use crate::error::ArtifactError;
use crate::learning::honesty::HONESTY_AXIS;
use crate::skill_optimize::{
    AxisScores, GoalAxisBandit, GoalAxisPlan, GoalAxisReport, OnlineAxisOutcome, measure_goal_axes,
};
use serde::{Deserialize, Serialize};

const LIVE_PREFIX: &[u8] = b"skill_optimize/live_axes/v2\0";
const PLAN_DOMAIN: &[u8] = b"skill_optimize:live_axis_plan:v1\0";
const LABEL: &str = "skill live goal-axis row";
/// The mandatory cost axis the scorer reports in minutes on every case.
const HUMAN_MINUTES: &str = "human_minutes";

/// Dreamer re-measure passes after which an inconclusive primary axis closes
/// its proposal as Inconclusive (Engine 00:26 measured give-up).
const INCONCLUSIVE_GIVE_UP_PASSES: u32 = 5;
/// Passes over which a non-shrinking interval width closes early (Engine 00:26).
const INCONCLUSIVE_STALL_PASSES: u32 = 2;

/// Policy hook for the give-up pass limit: the ruled 5 today, a vault dial later.
pub(super) fn inconclusive_give_up_passes() -> u32 {
    INCONCLUSIVE_GIVE_UP_PASSES
}

/// Policy hook for the stall window: the ruled 2 today, a vault dial later.
pub(super) fn inconclusive_stall_passes() -> u32 {
    INCONCLUSIVE_STALL_PASSES
}

/// Which measured give-up fired (Engine 00:26): the pass limit or the stalled
/// width. The disposition string on the verdict row records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InconclusiveTrigger {
    /// The 5th re-measure pass still left a primary axis inconclusive.
    PassLimit,
    /// The interval width stopped shrinking over 2 passes.
    WidthStall,
}

impl InconclusiveTrigger {
    /// The terminal arm this trigger closes with.
    pub(super) fn disposition(self) -> SkillEditDisposition {
        match self {
            Self::PassLimit => SkillEditDisposition::InconclusiveExhausted,
            Self::WidthStall => SkillEditDisposition::InconclusiveStalled,
        }
    }
}

const fn retry(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::SkillEditGateRetry(reason))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveAxesRow {
    plan_digest: String,
    /// The effective goal revision measured: a revised goal (a new project
    /// goal claim, a rebind, an override) is measured again even when its
    /// axes keep their names and kinds.
    goal_revision: String,
    proposal_digest: String,
    target_digest: String,
    evidence_digest: String,
    /// The judge and rubric the report was measured by (FIX 8846).
    judge: JudgeBinding,
    report: GoalAxisReport,
    /// Per-axis interval widths of this pass: axis -> (before, after). The
    /// next pass compares against them; a row without them is a row from
    /// another contract and decodes as one (no serde defaults).
    prev_widths: BTreeMap<String, (f64, f64)>,
    /// Consecutive non-shrinking width comparisons over the inconclusive set.
    stall_streak: u32,
}

/// The axes a bound live report measured, and the primary axes it left
/// unknown.
#[derive(Default)]
pub(super) struct LiveAxes {
    pub(super) measured: BTreeMap<String, GoalAxisScore>,
    /// Primary axes whose online interval was inconclusive. The vector
    /// carries each as a tie, and the gate defers on it, never admits.
    pub(super) inconclusive: BTreeSet<String>,
}

fn key(proposal: &EntityId) -> Vec<u8> {
    [LIVE_PREFIX, proposal.as_bytes()].concat()
}

/// The plan a goal implies: primary axes online, floor and cost axes offline
/// on the held-out set. Human minutes are measured on every live run anyway,
/// and honesty is the gate's own audit, never a named score.
pub(super) fn goal_axis_plan(definition: &GoalDefinition, pulls_per_axis: u32) -> GoalAxisPlan {
    let mut plan = GoalAxisPlan {
        offline: Vec::new(),
        online: Vec::new(),
        pulls_per_axis,
    };
    for axis in &definition.axes {
        match axis.kind {
            GoalAxisKind::Primary => plan.online.push(axis.name.clone()),
            GoalAxisKind::Floor | GoalAxisKind::Cost
                if axis.name != HUMAN_MINUTES && axis.name != HONESTY_AXIS =>
            {
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
    measure_with_owner(vault, proposal, scorer, bandit, pulls_per_axis, None)
}

pub(crate) fn measure_skill_edit_goal_axes_as_owner(
    vault: &Vault,
    owner: &crate::consent::AuthenticatedOwner,
    proposal: &EntityId,
    scorer: &dyn HeldOutReplayNotes,
    bandit: &dyn GoalAxisBandit,
    pulls_per_axis: u32,
) -> Result<GoalAxisReport> {
    owner.revalidate(vault)?;
    measure_with_owner(vault, proposal, scorer, bandit, pulls_per_axis, Some(owner))
}

fn measure_with_owner(
    vault: &Vault,
    proposal: &EntityId,
    scorer: &dyn HeldOutReplayNotes,
    bandit: &dyn GoalAxisBandit,
    pulls_per_axis: u32,
    owner: Option<&crate::consent::AuthenticatedOwner>,
) -> Result<GoalAxisReport> {
    let staged = vault
        .get_skill_record(proposal)?
        .ok_or(Error::EntityNotFound)?;
    require_open_optimizer_proposal(&staged)?;
    let target = target_of(&staged)?;
    let current = vault
        .get_skill_record(&target)?
        .ok_or(Error::EntityNotFound)?;
    let (plan, goal_revision, judge) = {
        let txn = vault.store.env.read_txn()?;
        let definition = goal_definition_in_txn(vault, &txn, &target)?;
        (
            goal_axis_plan(&definition, pulls_per_axis),
            definition.revision,
            JudgeBinding::in_txn(vault, &txn, scorer.judge_revision())?,
        )
    };
    let report = measure_goal_axes(vault, target, &current, &staged, &plan, scorer, bandit)?;
    vault.with_write_txn_grouped(|txn| {
        if let Some(owner) = owner {
            owner.revalidate_in_txn(vault, txn)?;
        }
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
        let definition = goal_definition_in_txn(vault, txn, &target)?;
        if goal_axis_plan(&definition, pulls_per_axis) != plan
            || definition.revision != goal_revision
        {
            return Err(retry("the goal moved while its axes were measured"));
        }
        if JudgeBinding::in_txn(vault, txn, scorer.judge_revision())? != judge {
            return Err(retry(
                "the judge or its rubric moved while the goal axes were measured",
            ));
        }
        let widths = report_widths(&report);
        let unknown = report_inconclusive(&report);
        // The stall streak over the previous pass: a changed inconclusive set
        // is a new question, and an axis stalled only when NEITHER arm's
        // interval strictly shrank (separation needs the wider one to shrink).
        let stall_streak = match load(vault, &*txn, proposal)? {
            Some(prev)
                if !unknown.is_empty()
                    && report_inconclusive(&prev.report) == unknown
                    && unknown.iter().all(|axis| {
                        prev.prev_widths.get(axis).is_some_and(|(before, after)| {
                            widths.get(axis).is_some_and(|(cur_before, cur_after)| {
                                *cur_before >= *before && *cur_after >= *after
                            })
                        })
                    }) =>
            {
                prev.stall_streak.saturating_add(1)
            }
            _ => 0,
        };
        let row = LiveAxesRow {
            plan_digest: plan_digest(&plan),
            goal_revision,
            proposal_digest,
            target_digest,
            evidence_digest: evidence_identity(&held_out).1,
            judge,
            report: report.clone(),
            prev_widths: widths,
            stall_streak,
        };
        let bytes = rmp_serde::to_vec_named(&row)
            .map_err(|_| invalid("live goal-axis row encoding failed"))?;
        vault.store.vault_meta.put(txn, &key(proposal), &bytes)?;
        // The live runs are measured: the trial routes no more of them.
        crate::skill_optimize::exploration_trial::close_exploration_trial_in_txn(
            vault,
            txn,
            proposal,
            crate::skill_optimize::exploration_trial::ExplorationTrialClose::ReportStored,
        )
    })?;
    Ok(report)
}

/// Whether the gate waits on a live measurement of `proposal`: its goal is
/// joined to a project's goal record with primary axes, and no kept report
/// binds both current bodies, the reserved evidence, the goal's plan and
/// revision, and the judge and rubric `scorer` scores with now. A bound
/// report that left a primary axis inconclusive is measured again.
/// # Errors
/// A proposal that is not an open optimizer proposal, an unreadable target,
/// goal or rubric, or storage errors.
pub fn skill_edit_needs_goal_axis_report(
    vault: &Vault,
    proposal: &EntityId,
    scorer: &dyn HeldOutReplayNotes,
) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let staged = vault.read_skill_record_in_txn(&txn, proposal)?;
    require_open_optimizer_proposal(&staged)?;
    let target = target_of(&staged)?;
    let definition = goal_definition_in_txn(vault, &txn, &target)?;
    let plan = goal_axis_plan(&definition, 0);
    if definition.project.is_none() || plan.online.is_empty() {
        return Ok(false);
    }
    let current = vault.read_skill_record_in_txn(&txn, &target)?;
    let proposal_digest = skill_body_binding_digest(&staged)?;
    let target_digest = skill_body_binding_digest(&current)?;
    let evidence_digest = evidence_identity(&held_out_receipts_in_txn(vault, &txn, &target)?).1;
    let judge = JudgeBinding::in_txn(vault, &txn, scorer.judge_revision())?;
    Ok(!load(vault, &txn, proposal)?.is_some_and(|row| {
        binds(
            &row,
            &plan,
            &definition.revision,
            &proposal_digest,
            &target_digest,
            &evidence_digest,
            &judge,
        ) && inconclusive(&row).is_empty()
    }))
}

/// Whether `row` measured this exact basis on `plan`, under goal revision
/// `goal_revision`, by `judge`.
fn binds(
    row: &LiveAxesRow,
    plan: &GoalAxisPlan,
    goal_revision: &str,
    proposal: &str,
    target: &str,
    evidence: &str,
    judge: &JudgeBinding,
) -> bool {
    row.plan_digest == plan_digest(plan)
        && row.goal_revision == goal_revision
        && row.proposal_digest == proposal
        && row.target_digest == target
        && row.evidence_digest == evidence
        && row.judge == *judge
}

/// The primary axes `row` measured online with no conclusive interval.
fn inconclusive(row: &LiveAxesRow) -> BTreeSet<String> {
    report_inconclusive(&row.report)
}

/// The primary axes a report measured online with no conclusive interval.
fn report_inconclusive(report: &GoalAxisReport) -> BTreeSet<String> {
    report
        .online
        .iter()
        .filter(|axis| axis.outcome == OnlineAxisOutcome::Inconclusive)
        .map(|axis| axis.axis.clone())
        .collect()
}

/// Per-axis interval widths of a report: axis -> (before, after).
fn report_widths(report: &GoalAxisReport) -> BTreeMap<String, (f64, f64)> {
    report
        .online
        .iter()
        .map(|axis| {
            (
                axis.axis.clone(),
                (
                    axis.before.upper - axis.before.lower,
                    axis.after.upper - axis.after.lower,
                ),
            )
        })
        .collect()
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

/// The measured give-up for `proposal`, if it fired (Engine 00:26): the 5th
/// re-measure pass, or a width stalled over 2. The pass limit wins when both
/// fire. `None` while the proposal still has passes to spend.
pub(super) fn inconclusive_give_up_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    proposal: &EntityId,
) -> Result<Option<InconclusiveTrigger>> {
    let prior = decision::inconclusive_passes_in_txn(vault, rtxn, proposal)?;
    let limit = prior.saturating_add(1) >= inconclusive_give_up_passes();
    let stalled = load(vault, rtxn, proposal)?
        .is_some_and(|row| row.stall_streak.saturating_add(1) >= inconclusive_stall_passes());
    if limit {
        Ok(Some(InconclusiveTrigger::PassLimit))
    } else if stalled {
        Ok(Some(InconclusiveTrigger::WidthStall))
    } else {
        Ok(None)
    }
}

/// A score validated into 0..=1, which an f32 holds.
#[allow(clippy::cast_possible_truncation)]
fn narrow(score: f64) -> f32 {
    score as f32
}

fn midpoint(bounds: crate::skill_optimize::ConfidenceInterval) -> f32 {
    narrow(f64::midpoint(bounds.lower, bounds.upper))
}

/// Observed costs as scores, larger better: the cheaper arm scores 1 and the
/// other the share of its time the cheaper arm took. No scale is assumed.
fn cost_scores(minutes: AxisScores) -> (f32, f32) {
    let least = minutes.before.min(minutes.after);
    let score = |spent: f64| {
        if spent > 0.0 {
            narrow(least / spent)
        } else {
            1.0
        }
    };
    (score(minutes.before), score(minutes.after))
}

/// The measured axes of a project-bound goal's vector, from the live report
/// bound to this exact basis and to the judge `judge_revision` with the
/// rubric in force. The gate judges only the axes this leaves out, so nothing
/// measured is judged again as a 0..1 score. Other goals measure nothing here
/// and keep the replay. A failed offline preflight bound to the basis stands
/// in for the report: its floors and costs are the measured axes.
/// # Errors
/// The retryable outcome while neither a bound report nor a bound failed
/// preflight exists, or a row naming an axis the goal lacks.
pub(super) fn live_axes(
    vault: &Vault,
    proposal: &EntityId,
    basis: &ScoredBasis,
    definition: &GoalDefinition,
    judge_revision: &str,
) -> Result<LiveAxes> {
    if definition.project.is_none() {
        return Ok(LiveAxes::default());
    }
    let plan = goal_axis_plan(definition, 0);
    if plan.online.is_empty() {
        return Ok(LiveAxes::default());
    }
    let txn = vault.store.env.read_txn()?;
    let row = load(vault, &txn, proposal)?;
    let judge = JudgeBinding::in_txn(vault, &txn, judge_revision)?;
    drop(txn);
    let Some(row) = row.filter(|row| {
        binds(
            row,
            &plan,
            &basis.goal_revision,
            &basis.proposal_digest,
            &basis.target_digest,
            &basis.evidence_digest,
            &judge,
        )
    }) else {
        // A floor that regressed offline on this basis opened no trial: the
        // failed preflight is the evidence, and the floor rejects.
        let failed = super::preflight::failed_preflight_axes(
            vault,
            proposal,
            basis,
            definition,
            judge_revision,
        )?;
        return failed
            .map(|measured| LiveAxes {
                measured,
                inconclusive: BTreeSet::new(),
            })
            .ok_or(retry(
                "a project goal's primary axes need a live measurement of this proposal first",
            ));
    };
    let kind = |name: &str| {
        definition
            .axes
            .iter()
            .find(|axis| axis.name == name)
            .map(|axis| axis.kind)
    };
    let mut measured = BTreeMap::new();
    let unknown = inconclusive(&row);
    for axis in &row.report.online {
        let before = midpoint(axis.before);
        let after = match axis.outcome {
            // Unknown, carried as a tie: the gate defers on it.
            OnlineAxisOutcome::Inconclusive => before,
            OnlineAxisOutcome::CandidateBetter | OnlineAxisOutcome::IncumbentBetter => {
                midpoint(axis.after)
            }
        };
        let kind = kind(&axis.axis).ok_or(Error::CorruptedIndex(LABEL))?;
        measured.insert(
            axis.axis.clone(),
            GoalAxisScore {
                kind,
                before,
                after,
            },
        );
    }
    for (name, scores) in &row.report.offline {
        let kind = kind(name).ok_or(Error::CorruptedIndex(LABEL))?;
        measured.insert(
            name.clone(),
            GoalAxisScore {
                kind,
                before: narrow(scores.before),
                after: narrow(scores.after),
            },
        );
    }
    // Unknown person-time on either arm is no measured difference: a tie.
    if let Some(kind) = kind(HUMAN_MINUTES) {
        let (before, after) = row.report.human_minutes.map_or((1.0, 1.0), cost_scores);
        measured.insert(
            HUMAN_MINUTES.to_owned(),
            GoalAxisScore {
                kind,
                before,
                after,
            },
        );
    }
    Ok(LiveAxes {
        measured,
        inconclusive: unknown,
    })
}
