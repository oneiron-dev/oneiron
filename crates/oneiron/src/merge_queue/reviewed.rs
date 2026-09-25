//! Production landing through immutable multi-critic proposal approvals.
use super::{LandingPermit, MergeBatch, MergeLanding, MergeQueue, TestedBatch};
use crate::{Vault, codebase::RepoRef, error::Result, repo_mutation::RepoMutationOutcome};

/// Uses the engine's durable reviewed proposal journal, not a trusted-admin
/// mutation door. Each merge proposal ID must name exactly one repository
/// proposal. Every member must have independent unanimous critic acceptance.
pub struct ReviewedProposalLanding<'a> {
    vault: &'a Vault,
    repo: RepoRef,
}
impl<'a> ReviewedProposalLanding<'a> {
    #[must_use]
    pub fn new(vault: &'a Vault, repo: RepoRef) -> Self {
        Self { vault, repo }
    }
}
impl MergeLanding for ReviewedProposalLanding<'_> {
    fn land(
        &mut self,
        permit: &LandingPermit,
        tested: &TestedBatch,
    ) -> Result<Vec<RepoMutationOutcome>> {
        self.vault
            .apply_tested_repo_proposals(&self.repo, permit, tested)
    }
}
impl MergeQueue<'_> {
    /// Land only immutable, unanimously reviewed proposals matching every tested
    /// byte. All members are admitted atomically before any effect. An interrupted
    /// stack resumes through `recover`, using only its exact persisted prefix.
    pub fn land_reviewed(&self, id: &str) -> Result<MergeBatch> {
        self.land(
            id,
            &mut ReviewedProposalLanding::new(self.vault, self.repo.repo_ref().clone()),
        )
    }
}
