//! Coverage is a goal-record floor, not a skill quality-diversity archive.
//! Replay arms are projected through the SAME pinned output descriptor. The
//! floor requires retention of every incumbent kind, not merely an equal
//! number of different kinds or a larger archive accumulated across old runs.

use std::collections::BTreeSet;

use crate::llm::decision::{DecisionQuestion, TypedDecision};
use crate::skill_optimize::{
    GoalAxisKind, GoalAxisScore, GoalAxisSpec, HeldOutReplayCase, HeldOutReplayNotes,
    HonestyReplay, SkillOptimizeDecisions, SkillReplayPair,
};
use crate::workspace_roster::GoalRecord;
use crate::{EntityId, Error, Result};

use super::CampaignResult;
use super::archive::{
    ArchiveCell, ArchiveOutputRef, CampaignArchivePin, OutputArchive, invalid, nonblank,
};

/// Exact skill body and held-out identities that produced one arm's outputs.
/// Output refs resolve to receipts in the archive, never directly to a score.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageReplay {
    skill: EntityId,
    skill_id: String,
    version: String,
    instructions_digest: String,
    held_out_receipts: Vec<String>,
    outputs: Vec<ArchiveOutputRef>,
}

impl CoverageReplay {
    pub fn from_case(
        case: &HeldOutReplayCase<'_>,
        outputs: Vec<ArchiveOutputRef>,
    ) -> CampaignResult<Self> {
        nonblank(case.skill_id, "coverage skill id")?;
        nonblank(case.version, "coverage skill version")?;
        nonblank(case.instructions, "coverage skill instructions")?;
        if case.held_out_receipts.is_empty() {
            return invalid("coverage replay", "held-out receipts are required");
        }
        let mut receipts = BTreeSet::new();
        for receipt in case.held_out_receipts {
            nonblank(receipt, "coverage held-out receipt")?;
            if !receipts.insert(receipt.clone()) {
                return invalid("coverage replay", "duplicate held-out receipt");
            }
        }
        Ok(Self {
            skill: case.skill,
            skill_id: case.skill_id.to_owned(),
            version: case.version.to_owned(),
            instructions_digest: instructions_digest(case.instructions),
            held_out_receipts: receipts.into_iter().collect(),
            outputs,
        })
    }

    fn matches(&self, case: &HeldOutReplayCase<'_>) -> bool {
        let mut receipts = case.held_out_receipts.to_vec();
        receipts.sort();
        self.matches_body(case) && self.held_out_receipts == receipts
    }

    fn matches_body(&self, case: &HeldOutReplayCase<'_>) -> bool {
        self.skill == case.skill
            && self.skill_id == case.skill_id
            && self.version == case.version
            && self.instructions_digest == instructions_digest(case.instructions)
    }

    fn matches_replay(&self, case: &HeldOutReplayCase<'_>) -> bool {
        self.matches_body(case)
            && !case.held_out_receipts.is_empty()
            && case
                .held_out_receipts
                .iter()
                .all(|receipt| self.held_out_receipts.binary_search(receipt).is_ok())
    }
}

/// A disposable floor projection over two held-out replay arms. Fields are
/// private and never deserialized, so a caller cannot supply fabricated cells.
#[derive(Debug, Clone, PartialEq)]
pub struct CoverageFloorComparison {
    pin: CampaignArchivePin,
    before: CoverageReplay,
    after: CoverageReplay,
    before_cells: BTreeSet<ArchiveCell>,
    after_cells: BTreeSet<ArchiveCell>,
}

impl CoverageFloorComparison {
    pub fn project(
        goal: &GoalRecord,
        archive: &OutputArchive,
        before: CoverageReplay,
        after: CoverageReplay,
    ) -> CampaignResult<Self> {
        check_floor(goal)?;
        archive.pin().check_goal(goal)?;
        if before.skill != after.skill
            || before.skill_id != after.skill_id
            || before.held_out_receipts != after.held_out_receipts
        {
            return invalid(
                "coverage replay",
                "arms must replay the same skill and held-out cases",
            );
        }
        let before_cells = archive.coverage(&before.outputs)?;
        let after_cells = archive.coverage(&after.outputs)?;
        if before_cells.is_empty() {
            return invalid(
                "coverage floor",
                "incumbent coverage is unknown without outputs",
            );
        }
        if before.version == after.version
            && before.instructions_digest == after.instructions_digest
            && before_cells != after_cells
        {
            return invalid(
                "coverage replay",
                "one skill body cannot have conflicting arm coverage",
            );
        }
        Ok(Self {
            pin: archive.pin().clone(),
            before,
            after,
            before_cells,
            after_cells,
        })
    }

    pub fn pin(&self) -> &CampaignArchivePin {
        &self.pin
    }

    pub fn before_cells(&self) -> &BTreeSet<ArchiveCell> {
        &self.before_cells
    }

    pub fn after_cells(&self) -> &BTreeSet<ArchiveCell> {
        &self.after_cells
    }

    pub fn lost_cells(&self) -> impl Iterator<Item = &ArchiveCell> {
        self.before_cells.difference(&self.after_cells)
    }

    pub fn preserves_coverage(&self) -> bool {
        self.before_cells.is_subset(&self.after_cells)
    }

    /// Binary no-regression floor: 1 means every incumbent kind survives.
    /// Extra kinds are reported above, but never offset a lost incumbent kind.
    /// The landed admission gate rejects a regression even if quality rises.
    pub fn goal_axis_score(&self) -> GoalAxisScore {
        GoalAxisScore {
            kind: GoalAxisKind::Floor,
            before: 1.0,
            after: if self.preserves_coverage() { 1.0 } else { 0.0 },
        }
    }

    pub(crate) fn score_case(&self, case: &HeldOutReplayCase<'_>) -> Result<f32> {
        if self.before.matches(case) {
            Ok(1.0)
        } else if self.after.matches(case) {
            Ok(self.goal_axis_score().after)
        } else {
            Err(Error::InvalidConfig(
                "coverage evidence does not match the skill body and held-out replay".into(),
            ))
        }
    }
}

/// Decorates the existing admission scorer with measured output coverage.
/// The authenticated goal must ALREADY declare `coverage` as a floor; this
/// adapter cannot rewrite that goal, mint a preference or bypass the gate.
/// Measured coverage loss refuses scoring. All scores and judge audits use
/// the inner scorer's shared typed-decision path.
pub struct CoverageFloorScorer<'a> {
    inner: &'a dyn HeldOutReplayNotes,
    comparison: &'a CoverageFloorComparison,
}

impl<'a> CoverageFloorScorer<'a> {
    pub fn new(
        inner: &'a dyn HeldOutReplayNotes,
        comparison: &'a CoverageFloorComparison,
        goal: &GoalRecord,
    ) -> CampaignResult<Self> {
        check_floor(goal)?;
        comparison.pin.check_goal(goal)?;
        Ok(Self { inner, comparison })
    }
}

impl HeldOutReplayNotes for CoverageFloorScorer<'_> {
    fn judge_revision(&self) -> &str {
        self.inner.judge_revision()
    }

    fn decisions(&self) -> SkillOptimizeDecisions<'_> {
        self.inner.decisions()
    }

    fn replay_state(&self, case: &HeldOutReplayCase<'_>) -> Result<serde_json::Value> {
        // Task-success judgments replay one reserved receipt at a time.
        if !self.comparison.before.matches_replay(case)
            && !self.comparison.after.matches_replay(case)
        {
            return Err(Error::InvalidConfig(
                "coverage evidence does not match the skill body and held-out replay".into(),
            ));
        }
        if !self.comparison.preserves_coverage() {
            return Err(Error::InvalidConfig(
                "held-out replay loses required output coverage".into(),
            ));
        }
        Ok(serde_json::json!({
            "replay": self.inner.replay_state(case)?,
            "coverage_floor": self.comparison.goal_axis_score(),
        }))
    }

    fn blind_pairs(&self, task: &str, receipts: &[String]) -> Result<Vec<SkillReplayPair>> {
        self.inner.blind_pairs(task, receipts)
    }

    fn record_decision(
        &self,
        question: &DecisionQuestion,
        decision: &TypedDecision,
        state: &serde_json::Value,
    ) -> Result<()> {
        self.inner.record_decision(question, decision, state)
    }

    fn honesty_replays(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<HonestyReplay>> {
        self.inner.honesty_replays(case)
    }

    fn human_minutes(&self, case: &HeldOutReplayCase<'_>) -> Result<f64> {
        self.inner.human_minutes(case)
    }

    fn coverage_floor(&self) -> Option<&CoverageFloorComparison> {
        Some(self.comparison)
    }

    fn goal_axes(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<GoalAxisSpec>> {
        self.comparison.score_case(case)?;
        let axes = self.inner.goal_axes(case)?;
        if !axes
            .iter()
            .any(|axis| axis.name == "coverage" && axis.kind == GoalAxisKind::Floor)
        {
            return Err(Error::InvalidConfig(
                "admission goal must declare the coverage floor".into(),
            ));
        }
        Ok(axes)
    }
}

fn instructions_digest(instructions: &str) -> String {
    blake3::hash(instructions.as_bytes()).to_hex().to_string()
}

fn check_floor(goal: &GoalRecord) -> CampaignResult<()> {
    if !goal.floor_axes.iter().any(|axis| axis.name == "coverage")
        || goal
            .primary_axes
            .iter()
            .chain(&goal.cost_axes)
            .any(|axis| axis.name == "coverage")
    {
        return invalid(
            "coverage floor",
            "the human goal must declare coverage only as a floor",
        );
    }
    Ok(())
}
