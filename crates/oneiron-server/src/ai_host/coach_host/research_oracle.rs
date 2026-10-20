//! The research tick's goal oracle (FIX 1331). The engine runs one selection
//! round for each due campaign; the host tells it whether the campaign's
//! goal is met. That is GoalMet only when the registered replay judge
//! decided, at the existing confidence band, that every axis the campaign's
//! pinned goal states is met on every run the incumbent's search measurement
//! stands on. A campaign with no stated target, no grounded run or no judge
//! gets no signal, and its selection runs as before. The owner's own GoalMet
//! through `vault.research.select` stays as it is.
use oneiron::Vault;
use oneiron::autoreason_campaign::research::ResearchGoalBasis;
use oneiron::autoreason_campaign::selection::OracleSignal;
use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::dreamer_runner::maintenance::ResearchGoalOracle;
use oneiron::learning::honesty::HONESTY_AXIS;
use oneiron::skill_optimize::{GoalAxisKind, HeldOutReplayNotes, skill_edit_goal};
use serde_json::{Value, json};

use crate::server::SyncServer;

/// One `coach.research_select` job.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    // No judge: no goal can be verified, so every due round runs with no
    // signal.
    let judge = crate::replay_judge::registered().map(|judge| judge as &dyn HeldOutReplayNotes);
    vault.run_coach_research_select(admitted, &JudgeOracle { vault, judge }, now)
}

/// The registered judge, asked about one campaign's goal at a time.
struct JudgeOracle<'a> {
    vault: &'a Vault,
    judge: Option<&'a dyn HeldOutReplayNotes>,
}

impl ResearchGoalOracle for JudgeOracle<'_> {
    fn signal(&self, basis: &ResearchGoalBasis) -> oneiron::Result<OracleSignal> {
        let Some(judge) = self.judge else {
            return Ok(OracleSignal::NoSignal);
        };
        let Some(criteria) = stated_axes(self.vault, basis)? else {
            return Ok(OracleSignal::NoSignal);
        };
        let Some(arm) = self.vault.get_skill_record(&basis.skill)? else {
            return Ok(OracleSignal::NoSignal);
        };
        if basis.receipts.is_empty() {
            return Ok(OracleSignal::NoSignal);
        }
        for criterion in &criteria {
            for receipt in &basis.receipts {
                // Only a decided yes verifies an axis: a no, an abstained or
                // escalated finding, or a run the judge cannot replay leaves
                // the goal unverified.
                if !judge
                    .live_axis_met(basis.skill, &arm, receipt, criterion)
                    .unwrap_or(false)
                {
                    return Ok(OracleSignal::NoSignal);
                }
            }
        }
        Ok(OracleSignal::GoalMet)
    }
}

/// Every axis the campaign's pinned goal states, as the judge's criterion:
/// each primary, floor and cost axis of the joined project's goal record,
/// with its measure and bound, as the live slice joins them. `None` when the
/// campaign has no target: the skill's goal is no longer the pinned one, no
/// project goal is joined, the record states no axis, or a task axis of the
/// skill's goal has no stated bound. The honesty floor is the engine's own
/// audit, so only a record that states it puts it to the judge.
fn stated_axes(vault: &Vault, basis: &ResearchGoalBasis) -> oneiron::Result<Option<Vec<Value>>> {
    let goal = skill_edit_goal(vault, &basis.skill)?;
    if goal.goal_id != basis.pin.goal_id || goal.revision != basis.pin.revision {
        return Ok(None);
    }
    let Some((project, _)) = basis.pin.project else {
        return Ok(None);
    };
    let Some(record) = vault.project_intake_goal(project)? else {
        return Ok(None);
    };
    let stated: Vec<_> = record
        .primary_axes
        .iter()
        .map(|axis| (GoalAxisKind::Primary, axis))
        .chain(
            record
                .floor_axes
                .iter()
                .map(|axis| (GoalAxisKind::Floor, axis)),
        )
        .chain(
            record
                .cost_axes
                .iter()
                .map(|axis| (GoalAxisKind::Cost, axis)),
        )
        .collect();
    let unstated = goal
        .axes
        .iter()
        .filter(|axis| axis.name != HONESTY_AXIS)
        .any(|axis| !stated.iter().any(|(_, named)| named.name == axis.name));
    if stated.is_empty() || unstated {
        return Ok(None);
    }
    Ok(Some(
        stated
            .into_iter()
            .map(|(kind, axis)| {
                json!({
                    "name": axis.name, "kind": kind, "measure": axis.measure, "bound": axis.bound,
                    "goal": record.goal, "why": record.why, "goal_revision": goal.revision,
                })
            })
            .collect(),
    ))
}
