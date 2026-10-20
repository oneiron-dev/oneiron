//! The goal-axis bandit's live arm attribution for one open optimizer
//! proposal, on the serve judge's arms: each pull's axis question is asked
//! of that judge, or of one a caller lends it.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};

use oneiron::posterior::Posterior;
use oneiron::receipt::{ReceiptKind, ReceiptQuery};
use oneiron::skill::SkillRecord;
use oneiron::skill_attribution::{AttributionVerdict, attribution_judgments};
use oneiron::skill_optimize::{
    AxisArm, ConfidenceInterval, GoalAxisBandit, HeldOutReplayNotes, OnlineAxisSample,
    PROVENANCE_OPTIMIZE_OF_ENTITY_KEY, skill_edit_goal,
};
use oneiron::skill_reliability::{SkillReliabilityPosterior, effective_skill_outcome};
use oneiron::{EntityId, Error, Result};
use serde_json::{Value, json};

use super::{ATTEMPT_RECEIPT, ServeReplayJudge, invalid, now, person_minutes};

/// How far back live arm attribution looks for loaded runs.
const LIVE_WINDOW_SECS: u64 = 30 * 86_400;
/// Most receipts one live pull scans.
const LIVE_SCAN_LIMIT: usize = 2_000;
/// The attempt state of a run that finished.
const COMPLETED: &str = "completed";

/// One arm of a live slice: the skill version its runs loaded, and the
/// record whose instructions an axis question reads beside each of them.
struct Arm {
    loaded: String,
    skill: EntityId,
    record: SkillRecord,
}

/// Live arm attribution for one open optimizer proposal: the incumbent arm
/// is the skill version it revises, the candidate arm the proposal. A pull
/// takes the newest run its axis has not taken yet that loaded the arm's
/// version. It met
/// the pulled axis when it completed, no skill-defect judgment names it, and
/// the judge it asks decides it met that axis by the axis's measure and bound.
/// Its person-time is what is recorded on its receipt, unknown when none is.
pub struct ServeAxisBandit<'a> {
    judge: &'a ServeReplayJudge,
    /// The judge each pull's axis question is asked of: the serve judge
    /// itself, or one a caller lent on its own clock.
    notes: &'a dyn HeldOutReplayNotes,
    /// The active skill the proposal revises, whose goal it is measured on.
    target: EntityId,
    incumbent: Arm,
    candidate: Arm,
    /// Each axis of the goal, with its measure and bound, and the goal and
    /// its why, where the joined project's goal record states them.
    criteria: BTreeMap<String, Value>,
    /// The runs each axis has pulled, by axis: every routed run is judged
    /// once on each axis.
    taken: Mutex<BTreeSet<(String, String)>>,
}

fn provenance_str(provenance: &rmpv::Value, key: &str) -> Option<String> {
    let rmpv::Value::Map(entries) = provenance else {
        return None;
    };
    entries
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .and_then(|(_, value)| value.as_str().map(str::to_owned))
}

impl<'a> ServeAxisBandit<'a> {
    /// The slice of `proposal` on `judge`. It words the goal's axes first, so
    /// a measure in a fresh process asks worded questions.
    /// # Errors
    /// A proposal that names no skill it revises, an unreadable goal or
    /// project goal record, or storage errors.
    pub fn for_proposal(judge: &'a ServeReplayJudge, proposal: &EntityId) -> Result<Self> {
        Self::judged_by(judge, proposal, judge)
    }

    /// The slice of `proposal` on `judge`'s arms, each pull's axis question
    /// asked of `notes`: the Coach lends its judge on the wake pass's clock,
    /// so a pull it starts stops by the time the pass has left.
    /// # Errors
    /// As [`Self::for_proposal`].
    pub fn judged_by(
        judge: &'a ServeReplayJudge,
        proposal: &EntityId,
        notes: &'a dyn HeldOutReplayNotes,
    ) -> Result<Self> {
        let vault = &judge.vault;
        let staged = vault
            .get_skill_record(proposal)?
            .ok_or(Error::EntityNotFound)?;
        let target = provenance_str(&staged.provenance, PROVENANCE_OPTIMIZE_OF_ENTITY_KEY)
            .and_then(|hex| EntityId::from_hex(&hex).ok())
            .ok_or_else(|| invalid("an optimizer proposal names the skill it revises"))?;
        let current = vault
            .get_skill_record(&target)?
            .ok_or(Error::EntityNotFound)?;
        let goal = skill_edit_goal(vault, &target)?;
        judge.word_axes(&goal.axes);
        let mut criteria: BTreeMap<String, Value> = goal
            .axes
            .iter()
            .map(|axis| {
                let criterion = json!({"name": axis.name, "goal_revision": goal.revision});
                (axis.name.clone(), criterion)
            })
            .collect();
        if let Some((project, _)) = goal.project
            && let Some(record) = vault.project_intake_goal(project)?
        {
            for axis in record
                .primary_axes
                .iter()
                .chain(&record.floor_axes)
                .chain(&record.cost_axes)
            {
                if let Some(criterion) = criteria.get_mut(&axis.name) {
                    *criterion = json!({
                        "name": axis.name, "measure": axis.measure, "bound": axis.bound,
                        "goal": record.goal, "why": record.why, "goal_revision": goal.revision,
                    });
                }
            }
        }
        Ok(Self {
            judge,
            notes,
            target,
            incumbent: Arm {
                loaded: format!("{}@{}", current.skill_id, current.version),
                skill: target,
                record: current,
            },
            candidate: Arm {
                loaded: format!("{}@{}", staged.skill_id, staged.version),
                skill: *proposal,
                record: staged,
            },
            criteria,
            taken: Mutex::new(BTreeSet::new()),
        })
    }

    /// Whether `receipt`'s run met `criterion` under `arm`'s instructions.
    fn met(&self, arm: &Arm, receipt: &str, criterion: &Value) -> Result<bool> {
        self.notes
            .live_axis_met(self.target, &arm.record, receipt, criterion)
    }
}

impl GoalAxisBandit for ServeAxisBandit<'_> {
    fn pull(&self, axis: &str, arm: AxisArm) -> Result<OnlineAxisSample> {
        let criterion = self
            .criteria
            .get(axis)
            .ok_or_else(|| invalid(format!("the goal names no {axis} axis")))?;
        let arm = match arm {
            AxisArm::Incumbent => &self.incumbent,
            AxisArm::Candidate => &self.candidate,
        };
        let vault = &self.judge.vault;
        let since = now().saturating_sub(LIVE_WINDOW_SECS);
        let mut scan = vault
            .scan_receipts(
                ReceiptQuery::new(LIVE_SCAN_LIMIT)
                    .with_kind(ReceiptKind::Outbound)
                    .with_time_bounds(Some(since), None),
            )?
            .records;
        scan.sort_by(|a, b| b.occurred_at.cmp(&a.occurred_at));
        let mut taken = self.taken.lock().unwrap_or_else(PoisonError::into_inner);
        let run = scan
            .into_iter()
            .find(|receipt| {
                receipt.receipt_id.starts_with(ATTEMPT_RECEIPT)
                    && !taken.contains(&(axis.to_owned(), receipt.receipt_id.clone()))
                    && receipt
                        .pack_manifest_skills()
                        .is_some_and(|skills| skills.contains(&arm.loaded))
            })
            .ok_or_else(|| invalid(format!("no live run of {} is left to pull", arm.loaded)))?;
        taken.insert((axis.to_owned(), run.receipt_id.clone()));
        drop(taken);
        let defect = attribution_judgments(vault)?.into_iter().any(|judgment| {
            judgment.verdict == AttributionVerdict::SkillDefect
                && judgment.subject == arm.skill
                && judgment.evidence_receipts.contains(&run.receipt_id)
        });
        // A run that failed or carries a defect misses every axis; only a
        // clean run is put to the axis question. The arm's outcome ledger,
        // once it holds the run (amendments and late credit applied),
        // outranks the attempt's own state.
        let won = effective_skill_outcome(vault, &arm.skill, &run.receipt_id)?
            .unwrap_or(run.outcome == COMPLETED);
        let success = won && !defect && self.met(arm, &run.receipt_id, criterion)?;
        Ok(OnlineAxisSample {
            success,
            human_minutes: person_minutes(vault, &run.receipt_id)?,
        })
    }

    /// The Beta posterior over the arm's wins from a flat prior: its lower
    /// bound, and as the upper bound one less the lower bound of its mirror.
    fn confidence_interval(
        &self,
        _axis: &str,
        _arm: AxisArm,
        wins: u32,
        pulls: u32,
    ) -> Result<ConfidenceInterval> {
        if wins > pulls {
            return Err(invalid("more wins than pulls"));
        }
        #[expect(
            clippy::cast_precision_loss,
            reason = "pull counts stay far below 2^24"
        )]
        let posterior = SkillReliabilityPosterior {
            alpha: 1.0 + wins as f32,
            beta: 1.0 + (pulls - wins) as f32,
        };
        let mirror = SkillReliabilityPosterior {
            alpha: posterior.beta,
            beta: posterior.alpha,
        };
        Ok(ConfidenceInterval {
            lower: Posterior::lower_bound(&posterior),
            upper: 1.0 - Posterior::lower_bound(&mirror),
        })
    }
}
