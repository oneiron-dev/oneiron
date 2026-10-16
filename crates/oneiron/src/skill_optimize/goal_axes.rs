//! Goal-axis measurements for the goal-record admission door.
//!
//! This does not grant an optimizer edit. The human-owned goal record and its
//! budget lease are separate doors; a report cannot replace their decision.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning::honesty::HONESTY_AXIS;
use crate::skill::SkillRecord;

use super::gate::{HeldOutReplayCase, held_out_receipts, skill_body_binding_digest};

/// Offline axes are judged on the reserved set; online axes sample live arms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalAxisPlan {
    pub offline: Vec<String>,
    pub online: Vec<String>,
    /// Maximum number of pulls across BOTH arms of EACH online axis.
    pub pulls_per_axis: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AxisScores {
    pub before: f64,
    pub after: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxisArm {
    Incumbent,
    Candidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    pub lower: f64,
    pub upper: f64,
}

/// One attributed live observation, including the person's time spent on it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OnlineAxisSample {
    /// Whether the run met the pulled axis, never one signal for every axis.
    pub success: bool,
    /// The person-time recorded on the run, in minutes. `None` when none is:
    /// unknown time, never zero.
    pub human_minutes: Option<f64>,
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

/// A host's live slices: the bandit for one open optimizer proposal, whose
/// arms are the skill it revises and the proposal itself.
pub trait GoalAxisBandits {
    /// # Errors
    /// A proposal that names no skill it revises, or storage errors.
    fn for_proposal(&self, proposal: &EntityId) -> Result<Box<dyn GoalAxisBandit + '_>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnlineAxisOutcome {
    CandidateBetter,
    IncumbentBetter,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnlineAxisMeasurement {
    pub axis: String,
    pub before_pulls: u32,
    pub after_pulls: u32,
    pub before: ConfidenceInterval,
    pub after: ConfidenceInterval,
    /// Person-time recorded on the slice's runs, by arm, in minutes.
    pub human_minutes: AxisScores,
    /// The pulls of each arm whose run carried recorded person-time.
    pub before_timed: u32,
    pub after_timed: u32,
    pub outcome: OnlineAxisOutcome,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoalAxisReport {
    pub held_out_receipts: Vec<String>,
    pub offline: Vec<(String, AxisScores)>,
    pub online: Vec<OnlineAxisMeasurement>,
    /// Mandatory cost axis: the mean person-time of one timed live run, by
    /// arm, in minutes. `None` while either arm has no timed run. Never
    /// included in an online success rate.
    pub human_minutes: Option<AxisScores>,
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
    let mut timed = [0u32; 2];
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
        if let Some(spent) = sample.human_minutes {
            human_minutes[chosen] = minutes(human_minutes[chosen] + minutes(spent)?)?;
            timed[chosen] += 1;
        }
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
        before_timed: timed[0],
        after_timed: timed[1],
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
/// every offline score validates may a live pull occur. The bandit observes a
/// caller-funded, capped slice per online axis; overlapping intervals are
/// inconclusive, never promoted as an improvement. Human minutes are the live
/// runs' recorded person-time, per arm: the reserved runs all ran the
/// incumbent, so they cannot tell the two arms' costs apart.
///
/// No axis from this report alone authorizes admission. The gate's door for
/// it is `measure_skill_edit_goal_axes`, which binds the report to the bodies,
/// evidence and plan, and lets a project goal's vector take its measured axes
/// from it; the honesty audit, floors, preferences and the responsible role
/// still rule there.
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
    replay: &dyn super::HeldOutReplayNotes,
    bandit: &dyn GoalAxisBandit,
) -> Result<GoalAxisReport> {
    if (plan.offline.is_empty() && plan.online.is_empty())
        || (!plan.online.is_empty() && plan.pulls_per_axis < 2)
    {
        return Err(invalid(
            "goal-axis plan needs an axis and at least two pulls per online axis",
        ));
    }
    // Honesty is the gate's own audit, never a named score.
    let mut names = HashSet::new();
    for name in plan.offline.iter().chain(&plan.online) {
        if name.trim().is_empty()
            || name == "human_minutes"
            || name == HONESTY_AXIS
            || !names.insert(name)
        {
            return Err(invalid(
                "goal-axis names must be unique, nonempty and not human_minutes or honesty",
            ));
        }
    }
    // The partition is keyed by ENTITY, not by skill_id. Bind the supplied
    // incumbent to that entity before showing any evidence to the scorer or
    // spending a live pull. The existing body digest excludes state axes and
    // the projector-updated confidence cache, but binds the measured content.
    let stored = vault
        .get_skill_record(&skill)?
        .ok_or(crate::error::Error::EntityNotFound)?;
    if skill_body_binding_digest(&stored)? != skill_body_binding_digest(incumbent)? {
        return Err(invalid(
            "goal-axis incumbent does not match the stored skill",
        ));
    }
    if candidate.skill_id != stored.skill_id {
        return Err(invalid("goal-axis candidate must name the measured skill"));
    }
    let held_out = held_out_receipts(vault, &skill)?;
    if held_out.is_empty() {
        return Err(invalid("goal-axis measurement requires held-out evidence"));
    }
    let before_case = replay_case(skill, incumbent, &held_out);
    let after_case = replay_case(skill, candidate, &held_out);
    let mut offline = Vec::with_capacity(plan.offline.len());
    for axis in &plan.offline {
        offline.push((
            axis.clone(),
            AxisScores {
                before: score(f64::from(replay.score_named_axis(&before_case, axis)?))?,
                after: score(f64::from(replay.score_named_axis(&after_case, axis)?))?,
            },
        ));
    }
    let mut spent = [0.0f64; 2];
    let mut timed = [0u32; 2];
    let mut online = Vec::with_capacity(plan.online.len());
    for axis in &plan.online {
        let measured = online_axis(axis, plan.pulls_per_axis, bandit)?;
        spent[0] = minutes(spent[0] + measured.human_minutes.before)?;
        spent[1] = minutes(spent[1] + measured.human_minutes.after)?;
        timed[0] += measured.before_timed;
        timed[1] += measured.after_timed;
        online.push(measured);
    }
    let human_minutes = (timed[0] > 0 && timed[1] > 0).then(|| AxisScores {
        before: spent[0] / f64::from(timed[0]),
        after: spent[1] / f64::from(timed[1]),
    });
    Ok(GoalAxisReport {
        held_out_receipts: held_out,
        offline,
        online,
        human_minutes,
    })
}
