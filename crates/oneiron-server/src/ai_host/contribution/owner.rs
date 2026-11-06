//! The owner's route for an `OwnerVerdict` anchor's contribution pair (FIX
//! 3609). The owner judges the pair: the engine keeps one pending pair and
//! asks the owner which of its two blinded answers pass, and the owner's own
//! counted word scores both forks. No model scores it. This scorer only
//! freezes the criterion both answers are judged against, before either
//! fork is paid for, and never decides a fork. It never waits for the owner,
//! and a pending pair reuses its kept forks.

use oneiron::Vault;
use oneiron::code_run::{
    ContributionForkScorer, ContributionReplayUnavailable, ReplayAnchor, ScoredFork,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill_attribution::ContributionCandidate;
use serde_json::json;

use super::goal_axis_anchor;
use crate::replay_judge::ServeReplayJudge;

/// The scorer identity an owner-judged pair is frozen under: the owner's
/// word on the pair's question, not a model.
const OWNER_PAIR_SCORER: &str = "owner_verdict/contribution_pair_question";

/// The owner's route for one wake pass.
pub(super) struct OwnerScorer {
    pub(super) judge: &'static ServeReplayJudge,
}

impl ContributionForkScorer for OwnerScorer {
    /// The criterion: the skill's goal axis the credit was anchored on, with
    /// the measure and bound the joined project's goal states for it, when
    /// one states it; else the axis by its name and the goal revision the
    /// credit was checked under, which the owner judges on the task itself.
    fn resolve(
        &self,
        vault: &Vault,
        candidate: &ContributionCandidate,
    ) -> oneiron::Result<Result<ReplayAnchor, ContributionReplayUnavailable>> {
        let rubric = match goal_axis_anchor(vault, candidate, self.judge)? {
            Some(anchor) => anchor.rubric,
            None => json!({ "name": candidate.axis, "goal_revision": candidate.goal_revision }),
        };
        Ok(Ok(ReplayAnchor {
            rubric,
            scorer: OWNER_PAIR_SCORER.to_owned(),
        }))
    }

    /// Never decides: only the owner's word scores an owner verdict's fork.
    fn passes(
        &self,
        _vault: &Vault,
        _candidate: &ContributionCandidate,
        _anchor: &ReplayAnchor,
        _fork: &ScoredFork<'_>,
        _clock: &RetrievalDeadline,
    ) -> oneiron::Result<Option<bool>> {
        Ok(None)
    }
}
