//! What the goal-intake interview reads first (OF-501): the goal claim in
//! force, its generation, the card draft the project was minted with, and the
//! loop's revision proposals. The draft and the proposals are a starting point
//! the human confirms or changes; nothing here writes or fills the goal.
use super::invalid;
use crate::genui::ProjectGoalDraft;
use crate::skill_optimize::{ProjectGoalRevisionProposal, project_goal_revision_proposals};
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
}

impl Vault {
    /// The goal in force, its generation and the card's draft, read in one
    /// snapshot, with the revision proposals under that same goal claim.
    pub fn project_goal_interview_context(
        &self,
        project: EntityId,
    ) -> Result<ProjectGoalInterviewContext> {
        // The public list reads its own snapshot; only the rows under the goal
        // claim this snapshot holds stay.
        let proposals = project_goal_revision_proposals(self, project)?;
        let txn = self.store.env.read_txn()?;
        let record = self
            .visible_project_in_txn(&txn, project)?
            .ok_or_else(invalid)?;
        let goal_claim = self
            .project_intake_goal_in_txn(&txn, project)?
            .map(|(id, _)| id);
        let generation = super::interview::generation(&self.store, &txn, project)?;
        Ok(ProjectGoalInterviewContext {
            goal_claim,
            generation,
            card_seed: record.goal_record.map(|seed| ProjectGoalDraft {
                goal: seed.goal,
                why: seed.why,
                axes: seed.axes,
            }),
            revision_proposals: proposals
                .into_iter()
                .filter(|row| Some(row.goal_claim) == goal_claim)
                .collect(),
        })
    }
}
