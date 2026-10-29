//! The decision host's caller of the session-branch claim merge (OF-493 row
//! G, FIX 1328): the useful-upstream question and the held-out replay score,
//! both on this host's ladder, under one clock.
use super::DecisionHost;
use oneiron::Vault;
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill_hub::{ClaimRefinementMergeAsk, ClaimRefinementMergeDisposition};

/// How long one claim refinement merge's questions may take together: the
/// useful-upstream yes/no and one replay score per arm.
const CLAIM_REFINEMENT_MERGE_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);

/// The held-out replay's wording of the `[0, 1]` score, the question's key.
const CLAIM_REPLAY_WORDING: &str = "How well does this claim fit the owner's held-out labels? \
Answer 1 when every label agrees with it, 0 when none does, and a value between by how many \
agree and how closely.";

impl DecisionHost {
    /// Merges the session-branch claim edit `ask` names into `vault`, at
    /// `at`, with this host's typed decisions: the useful-upstream question,
    /// and, on a yes, the held-out replay per arm. The owner's approve-once
    /// answer on the ask is the merge's consent; without it the merge waits.
    ///
    /// # Errors
    ///
    /// A host with no System One seat or house read, or the merge's own
    /// refusal.
    pub fn merge_claim_refinement(
        &self,
        vault: &Vault,
        ask: &ClaimRefinementMergeAsk,
        at: u64,
    ) -> oneiron::Result<ClaimRefinementMergeDisposition> {
        let deadline = RetrievalDeadline::after(CLAIM_REFINEMENT_MERGE_BUDGET);
        let useful = self.useful_upstream(&deadline)?;
        let replay = self.claim_replay(CLAIM_REPLAY_WORDING.to_owned(), &deadline);
        vault.merge_local_claim_refinement(ask, &useful, &replay, at)
    }
}
