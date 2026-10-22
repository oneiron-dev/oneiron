//! The owner's goal on a project tree revision (FIX 8706, CALL R3). Before a
//! revision that won on the scalar held-out score goes in force, each axis
//! of the project's goal record is scored on the same held-out runs through
//! the shared typed decision path, and the record rules the result. An axis
//! the owner set binds: a floor that regresses fails, a primary or cost axis
//! that loses fails unless one of his stated preferences approves exactly
//! that set of gains and losses, and a preference that rejects it fails. A
//! failed revision stays out of force and the journal says why. An axis the
//! judge does not measure is advisory, as is a project with no goal record
//! (or one that does not read): today's scalar win goes in force and the
//! journal records the gap, never as a measured vector win. The writer that
//! activates reads the goal claim again.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::skill_optimize::{
    GoalAxisKind, GoalAxisSpec, HeldOutReplayCase, HeldOutReplayNotes, TradeoffChoice,
    TradeoffRule, project_axes,
};
use crate::workspace_roster::GoalRecord;
use crate::{EntityId, Error, Result, Vault};

/// What the project's goal said of one revision, as the journal keeps it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UpkeepGoal {
    /// The project's goal claim the verdict read; `None` with no goal record,
    /// or one that does not read.
    pub(super) goal_claim: Option<EntityId>,
    /// Each axis of the goal record, scored or not.
    pub(super) axes: Vec<UpkeepAxis>,
    pub(super) verdict: UpkeepGoalVerdict,
    /// Why: the axis or preference that failed it, the preference that
    /// approved a loss, the axes left unmeasured, or the goal record missing.
    pub(super) basis: Vec<String>,
}

impl UpkeepGoal {
    /// The scalar win standing with no goal record to rule it, for `gap`.
    fn advisory(gap: &str) -> Self {
        Self {
            goal_claim: None,
            axes: Vec::new(),
            verdict: UpkeepGoalVerdict::ScalarWin,
            basis: vec![gap.to_owned()],
        }
    }
}

/// One goal axis on the held-out runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UpkeepAxis {
    name: String,
    kind: GoalAxisKind,
    /// The tree in force's and the revision's scores; `None` when the judge
    /// did not measure the axis.
    scores: Option<(f32, f32)>,
}

/// How the goal ruled one scalar win.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum UpkeepGoalVerdict {
    /// Every goal axis measured: none lost and at least one gained.
    VectorWin,
    /// The scalar win stands on advisory axes: no goal record, an axis left
    /// unmeasured, axes that tied, or a loss the owner's preference approved.
    ScalarWin,
    /// An axis or a preference the owner set rules the revision out.
    Failed,
}

/// The project's goal record as one snapshot reads it.
enum GoalRead {
    /// No goal record names the project.
    Absent,
    /// One is named but does not read.
    Unreadable,
    /// The goal claim and its record.
    Read(EntityId, GoalRecord),
}

fn read_goal_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, project: EntityId) -> Result<GoalRead> {
    match vault.project_intake_goal_in_txn(txn, project) {
        Ok(Some((claim, record))) => Ok(GoalRead::Read(claim, record)),
        Ok(None) => Ok(GoalRead::Absent),
        Err(Error::InvalidConfig(_) | Error::Record(_)) => Ok(GoalRead::Unreadable),
        Err(error) => Err(error),
    }
}

/// Judges the revision (`after`) against the tree in force (`before`) on
/// `project`'s goal record through `judge`, the shared typed decision path.
///
/// # Errors
///
/// Storage errors, and the judge's errors other than an abstention.
pub(super) fn judge_goal(
    vault: &Vault,
    judge: &dyn HeldOutReplayNotes,
    project: EntityId,
    before: &HeldOutReplayCase<'_>,
    after: &HeldOutReplayCase<'_>,
) -> Result<UpkeepGoal> {
    let read = {
        let txn = vault.store.env.read_txn()?;
        read_goal_in_txn(vault, &txn, project)?
    };
    let (goal_claim, record) = match read {
        GoalRead::Read(claim, record) => (claim, record),
        GoalRead::Absent => return Ok(UpkeepGoal::advisory("no_goal_record")),
        GoalRead::Unreadable => return Ok(UpkeepGoal::advisory("goal_unreadable")),
    };
    let mut axes = Vec::new();
    for axis in project_axes(&record) {
        let scores = match (score(judge, before, &axis)?, score(judge, after, &axis)?) {
            (Some(old), Some(new)) => Some((old, new)),
            _ => None,
        };
        axes.push(UpkeepAxis {
            name: axis.name,
            kind: axis.kind,
            scores,
        });
    }
    let (verdict, basis) = rule(&record, &axes);
    Ok(UpkeepGoal {
        goal_claim: Some(goal_claim),
        axes,
        verdict,
        basis,
    })
}

/// Whether the goal `goal` read still stands in the activating write: the
/// project's goal claim is the one it read, or it still has none that reads.
pub(super) fn holds_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
    goal: &UpkeepGoal,
) -> Result<bool> {
    let claim = match read_goal_in_txn(vault, txn, project)? {
        GoalRead::Read(claim, _) => Some(claim),
        GoalRead::Absent | GoalRead::Unreadable => None,
    };
    Ok(claim == goal.goal_claim)
}

/// `case`'s score on `axis`; `None` when the judge abstains (as the scalar
/// score reads an abstention) or scores outside `0..=1`: unmeasured.
fn score(
    judge: &dyn HeldOutReplayNotes,
    case: &HeldOutReplayCase<'_>,
    axis: &GoalAxisSpec,
) -> Result<Option<f32>> {
    match judge.score_goal_axis(case, axis) {
        Ok(score) if (0.0..=1.0).contains(&score) => Ok(Some(score)),
        Ok(_) | Err(Error::InvalidConfig(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// The verdict `record` rules on `axes` (CALL R3), and why.
fn rule(record: &GoalRecord, axes: &[UpkeepAxis]) -> (UpkeepGoalVerdict, Vec<String>) {
    let moved = |kept: fn(f32, f32) -> bool| -> BTreeSet<String> {
        axes.iter()
            .filter(|axis| {
                axis.scores
                    .is_some_and(|(before, after)| kept(before, after))
            })
            .map(|axis| axis.name.clone())
            .collect()
    };
    let gains = moved(|before, after| after > before);
    let losses = moved(|before, after| after < before);
    if let Some(floor) = axes
        .iter()
        .find(|axis| axis.kind == GoalAxisKind::Floor && losses.contains(&axis.name))
    {
        return (
            UpkeepGoalVerdict::Failed,
            vec![format!("floor_regressed:{}", floor.name)],
        );
    }
    let mut basis = Vec::new();
    if !losses.is_empty() {
        let ruling = preference_rules(record, axes)
            .into_iter()
            .find(|(rule, _)| rule.gains == gains && rule.losses == losses);
        match ruling {
            Some((rule, citation)) if rule.choice == TradeoffChoice::Approve => {
                basis.push(format!("approved_by:{citation}"));
            }
            Some((_, citation)) => {
                return (
                    UpkeepGoalVerdict::Failed,
                    vec![format!("rejected_by:{citation}")],
                );
            }
            None => {
                let lost = losses.iter().map(|axis| format!("axis_lost:{axis}"));
                return (UpkeepGoalVerdict::Failed, lost.collect());
            }
        }
    }
    let unmeasured: Vec<String> = axes
        .iter()
        .filter(|axis| axis.scores.is_none())
        .map(|axis| format!("unmeasured:{}", axis.name))
        .collect();
    if unmeasured.is_empty() && basis.is_empty() && !gains.is_empty() {
        return (UpkeepGoalVerdict::VectorWin, basis);
    }
    if unmeasured.is_empty() && basis.is_empty() {
        basis.push("axes_tied".to_owned());
    }
    basis.extend(unmeasured);
    (UpkeepGoalVerdict::ScalarWin, basis)
}

/// The goal record's stated preferences over `axes` as ladder rules, read
/// as L08-B's `project_rules` reads them: "prefer A over B" approves a
/// vector that gains A and loses B, and rejects one that gains B and loses
/// A; `+` joins several axes on a side. A preference that names no exact
/// axis set stays prose. `project_rules` takes a skill-goal join this
/// upkeep has none of; this copy goes once it takes the record.
fn preference_rules(record: &GoalRecord, axes: &[UpkeepAxis]) -> Vec<(TradeoffRule, String)> {
    let names = |side: &str| -> Option<BTreeSet<String>> {
        let set: BTreeSet<String> = side.split('+').map(|name| name.trim().to_owned()).collect();
        set.iter()
            .all(|name| axes.iter().any(|axis| &axis.name == name))
            .then_some(set)
    };
    let mut rules = Vec::new();
    for (index, preference) in record.preferences.iter().enumerate() {
        let (Some(prefer), Some(over)) = (names(&preference.prefer), names(&preference.over))
        else {
            continue;
        };
        if !prefer.is_disjoint(&over) {
            continue;
        }
        rules.push((
            TradeoffRule {
                gains: prefer.clone(),
                losses: over.clone(),
                choice: TradeoffChoice::Approve,
            },
            format!("project_preference:{index}"),
        ));
        rules.push((
            TradeoffRule {
                gains: over,
                losses: prefer,
                choice: TradeoffChoice::Reject,
            },
            format!("project_preference:{index}:reverse"),
        ));
    }
    rules
}
