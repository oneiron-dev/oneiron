//! Goal-axis measurements for the future goal-record admission door.
//!
//! This does not grant an optimizer edit. The human-owned goal record and its
//! budget lease are separate doors; a report cannot replace their decision.

use std::collections::HashSet;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::skill::SkillRecord;

use super::gate::{HeldOutReplayCase, held_out_receipts};

/// Offline axes are judged on the reserved set; online axes sample live arms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalAxisPlan {
    pub offline: Vec<String>,
    pub online: Vec<String>,
    /// Maximum number of pulls across BOTH arms of EACH online axis.
    pub pulls_per_axis: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AxisScores {
    pub before: f64,
    pub after: f64,
}

/// The scorer sees the same held-out receipt identities for both versions.
/// Human minutes are a cost (lower is better), not an inferred quality score.
pub trait GoalAxisScorer {
    fn offline_score(&self, axis: &str, case: &HeldOutReplayCase<'_>) -> Result<f64>;
    fn human_minutes(&self, case: &HeldOutReplayCase<'_>) -> Result<f64>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxisArm {
    Incumbent,
    Candidate,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ConfidenceInterval {
    pub lower: f64,
    pub upper: f64,
}

/// One attributed live observation, including the person's time spent on it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OnlineAxisSample {
    pub success: bool,
    pub human_minutes: f64,
}

/// Host-backed live samples and confidence bounds. No invented default: the
/// host must implement its outcome attribution and statistical bound. A caller
/// implementing a Beta bound should use `Posterior::lower_bound`, not a copy of
/// its formula. Each `pull` consumes one unit of the supplied slice budget.
pub trait GoalAxisBandit {
    fn pull(&self, axis: &str, arm: AxisArm) -> Result<OnlineAxisSample>;
    fn confidence_interval(
        &self,
        axis: &str,
        arm: AxisArm,
        wins: u32,
        pulls: u32,
    ) -> Result<ConfidenceInterval>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnlineAxisOutcome {
    CandidateBetter,
    IncumbentBetter,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OnlineAxisMeasurement {
    pub axis: String,
    pub before_pulls: u32,
    pub after_pulls: u32,
    pub before: ConfidenceInterval,
    pub after: ConfidenceInterval,
    /// Actual human time spent in the live slice, by arm.
    pub human_minutes: AxisScores,
    pub outcome: OnlineAxisOutcome,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GoalAxisReport {
    pub held_out_receipts: Vec<String>,
    pub offline: Vec<(String, AxisScores)>,
    pub online: Vec<OnlineAxisMeasurement>,
    /// Mandatory cost axis, in minutes; never included in an online success rate.
    pub human_minutes: AxisScores,
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

fn score(value: f64) -> Result<f64> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(invalid("goal-axis score must be finite in 0..=1"));
    }
    Ok(value)
}

fn minutes(value: f64) -> Result<f64> {
    if !value.is_finite() || value < 0.0 {
        return Err(invalid("human minutes must be finite and nonnegative"));
    }
    Ok(value)
}

fn bounds(value: ConfidenceInterval) -> Result<ConfidenceInterval> {
    score(value.lower)?;
    score(value.upper)?;
    if value.lower > value.upper {
        return Err(invalid("goal-axis confidence bounds are reversed"));
    }
    Ok(value)
}

fn interval(
    bandit: &dyn GoalAxisBandit,
    axis: &str,
    arm: AxisArm,
    wins: u32,
    pulls: u32,
) -> Result<ConfidenceInterval> {
    bounds(bandit.confidence_interval(axis, arm, wins, pulls)?)
}

fn online_axis(axis: &str, cap: u32, bandit: &dyn GoalAxisBandit) -> Result<OnlineAxisMeasurement> {
    let mut wins = [0u32; 2];
    let mut pulls = [0u32; 2];
    let mut human_minutes = [0.0f64; 2];
    let mut intervals = [ConfidenceInterval {
        lower: 0.0,
        upper: 1.0,
    }; 2];
    let arms = [AxisArm::Incumbent, AxisArm::Candidate];
    for step in 0..cap {
        // Explore each arm once before comparing bounds. Thereafter sample the
        // arm with the higher upper bound; ties alternate to avoid starvation.
        let chosen = if step < 2 {
            step as usize
        } else if intervals[0].upper > intervals[1].upper {
            0
        } else if intervals[1].upper > intervals[0].upper {
            1
        } else {
            (step % 2) as usize
        };
        let arm = arms[chosen];
        let sample = bandit.pull(axis, arm)?;
        human_minutes[chosen] = minutes(human_minutes[chosen] + minutes(sample.human_minutes)?)?;
        wins[chosen] += u32::from(sample.success);
        pulls[chosen] += 1;
        intervals[chosen] = interval(bandit, axis, arm, wins[chosen], pulls[chosen])?;
        if pulls[0] > 0
            && pulls[1] > 0
            && (intervals[1].lower > intervals[0].upper || intervals[0].lower > intervals[1].upper)
        {
            break;
        }
    }
    let outcome = if intervals[1].lower > intervals[0].upper {
        OnlineAxisOutcome::CandidateBetter
    } else if intervals[0].lower > intervals[1].upper {
        OnlineAxisOutcome::IncumbentBetter
    } else {
        OnlineAxisOutcome::Inconclusive
    };
    Ok(OnlineAxisMeasurement {
        axis: axis.to_owned(),
        before_pulls: pulls[0],
        after_pulls: pulls[1],
        before: intervals[0],
        after: intervals[1],
        human_minutes: AxisScores {
            before: human_minutes[0],
            after: human_minutes[1],
        },
        outcome,
    })
}

fn replay_case<'a>(
    skill: EntityId,
    record: &'a SkillRecord,
    receipts: &'a [String],
) -> HeldOutReplayCase<'a> {
    HeldOutReplayCase {
        skill,
        skill_id: &record.skill_id,
        version: &record.version,
        instructions: &record.desc,
        held_out_receipts: receipts,
    }
}

/// Measure offline axes on the vault's held-out evidence FIRST. Only after
/// every offline score and both human-minutes costs validate may a live pull
/// occur. The bandit observes a caller-funded, capped slice per online axis;
/// overlapping intervals are inconclusive, never promoted as an improvement.
///
/// No axis from this report alone authorizes admission: the goal-record owner,
/// preference and floor rules are not yet supplied by this seam.
///
/// # Errors
///
/// Empty or invalid plans, missing held-out evidence, bad scores/bounds, or
/// scorer, bandit and storage errors. No online pull occurs on an offline error.
pub fn measure_goal_axes(
    vault: &Vault,
    skill: EntityId,
    incumbent: &SkillRecord,
    candidate: &SkillRecord,
    plan: &GoalAxisPlan,
    scorer: &dyn GoalAxisScorer,
    bandit: &dyn GoalAxisBandit,
) -> Result<GoalAxisReport> {
    if plan.offline.is_empty() || (!plan.online.is_empty() && plan.pulls_per_axis < 2) {
        return Err(invalid(
            "goal-axis plan needs offline axes and at least two pulls per online axis",
        ));
    }
    let mut names = HashSet::new();
    for name in plan.offline.iter().chain(&plan.online) {
        if name.trim().is_empty() || name == "human_minutes" || !names.insert(name) {
            return Err(invalid(
                "goal-axis names must be unique, nonempty and not human_minutes",
            ));
        }
    }
    let held_out = held_out_receipts(vault, &skill)?;
    if held_out.is_empty() {
        return Err(invalid("goal-axis measurement requires held-out evidence"));
    }
    if incumbent.skill_id != candidate.skill_id {
        return Err(invalid("goal-axis pair must name the same skill"));
    }
    let before_case = replay_case(skill, incumbent, &held_out);
    let after_case = replay_case(skill, candidate, &held_out);
    let mut offline = Vec::with_capacity(plan.offline.len());
    for axis in &plan.offline {
        offline.push((
            axis.clone(),
            AxisScores {
                before: score(scorer.offline_score(axis, &before_case)?)?,
                after: score(scorer.offline_score(axis, &after_case)?)?,
            },
        ));
    }
    let mut human_minutes = AxisScores {
        before: minutes(scorer.human_minutes(&before_case)?)?,
        after: minutes(scorer.human_minutes(&after_case)?)?,
    };
    let mut online = Vec::with_capacity(plan.online.len());
    for axis in &plan.online {
        let measured = online_axis(axis, plan.pulls_per_axis, bandit)?;
        human_minutes.before = minutes(human_minutes.before + measured.human_minutes.before)?;
        human_minutes.after = minutes(human_minutes.after + measured.human_minutes.after)?;
        online.push(measured);
    }
    Ok(GoalAxisReport {
        held_out_receipts: held_out,
        offline,
        online,
        human_minutes,
    })
}
