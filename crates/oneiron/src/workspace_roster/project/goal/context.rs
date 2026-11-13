//! What the goal-intake interview reads first (OF-501): the goal claim in
//! force, its generation, the card draft the project was minted with, the
//! loop's preference proposals and the full goal proposals open on the goal
//! in force, each with its diff. The draft and the proposals are a starting
//! point the human confirms or changes; nothing here writes or fills the goal.
//! It also names the interview's thread and the run that asks in it.
use super::invalid;
use super::proposals::{
    ProjectGoalProposalStatus, ProjectGoalProposalView, project_goal_base_in_txn,
    project_goal_proposals_in_txn,
};
use crate::attempt_queue::AttemptId;
use crate::genui::ProjectGoalDraft;
use crate::skill_optimize::{ProjectGoalRevisionProposal, project_goal_revision_proposals_in_txn};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

/// The interview's seed for one project. A card's axes are names only: the
/// interview asks for each measure and bound, never fills them in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalInterviewContext {
    /// The goal claim in force; none before the first interview commits.
    pub goal_claim: Option<EntityId>,
    /// The goal generation a draft shown now is confirmed against.
    pub generation: u64,
    /// The card's draft the project was minted with: the interview's first turn.
    pub card_seed: Option<ProjectGoalDraft>,
    /// Preferences the loop proposes under the goal in force: optional, never merged.
    pub revision_proposals: Vec<ProjectGoalRevisionProposal>,
    /// Full goal proposals open on the goal in force, oldest first, each with
    /// its diff (floors named): arguments for the human, never merged. Only
    /// for a reader of the goal; empty for any other member.
    pub goal_proposals: Vec<ProjectGoalProposalView>,
    /// The open interview's thread root in the home room, the turn the
    /// leader's question answers: `None` once the confirmed goal committed,
    /// and for an interview the host opened no thread for.
    #[serde(default)]
    pub interview_thread: Option<EntityId>,
    /// The last intake run that loaded the goal-intake skill: the attempt a
    /// host completes the interview with. `None` before one loaded it. An
    /// attempt id grants no read.
    #[serde(default)]
    pub attempt_ref: Option<AttemptId>,
}

impl Vault {
    /// The goal in force, its generation, the card's draft, the preference
    /// proposals under that goal claim and, when `reads_goal`, the full
    /// proposals open on that goal, with the interview's thread and run, all
    /// read in one snapshot.
    pub fn project_goal_interview_context(
        &self,
        project: EntityId,
        reads_goal: bool,
    ) -> Result<ProjectGoalInterviewContext> {
        let txn = self.store.env.read_txn()?;
        self.project_goal_interview_context_in_txn(&txn, project, reads_goal)
    }

    /// [`Self::project_goal_interview_context`] in the caller's snapshot
    /// `txn`: a caller-facing read decides `reads_goal` in that same
    /// snapshot, so a disclosure check and the proposals it discloses never
    /// come from two snapshots.
    pub(crate) fn project_goal_interview_context_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        project: EntityId,
        reads_goal: bool,
    ) -> Result<ProjectGoalInterviewContext> {
        let record = self
            .visible_project_in_txn(txn, project)?
            .ok_or_else(invalid)?;
        let base = project_goal_base_in_txn(self, txn, project)?;
        let generation = super::interview::generation(&self.store, txn, project)?;
        let goal_proposals = if reads_goal {
            project_goal_proposals_in_txn(self, txn, project)?
                .into_iter()
                .map(|row| row.view(base.as_ref()))
                .filter(|view| view.status == ProjectGoalProposalStatus::Open)
                .collect()
        } else {
            Vec::new()
        };
        let interview = super::intake_run::interview_in_txn(&self.store, txn, project)?;
        Ok(ProjectGoalInterviewContext {
            goal_claim: base.map(|base| base.goal_claim),
            generation,
            card_seed: record.goal_record.map(|seed| ProjectGoalDraft {
                goal: seed.goal,
                why: seed.why,
                axes: seed.axes,
            }),
            revision_proposals: project_goal_revision_proposals_in_txn(self, txn, project)?,
            goal_proposals,
            interview_thread: interview
                .as_ref()
                .filter(|row| row.task.is_some())
                .map(|row| row.thread),
            attempt_ref: interview.and_then(|row| row.attempt),
        })
    }
}
