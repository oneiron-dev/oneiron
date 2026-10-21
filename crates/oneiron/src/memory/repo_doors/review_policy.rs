//! The stock review policy a host binds for runs' proposals (FIX 6867, G1
//! PR3b; FIX 8268).
//!
//! A run's proposal is held to the vault's own review policy
//! (`RepoProposalReview::VaultDefault`): the opt-in policy an Owner, or his
//! agent under its Grant, sets with `vault.code.merge_queue.review_policy.
//! set`, read by the merge queue's one policy point when it decides. With
//! none set the same checked queue lands it on green, never unchecked. The
//! older stock policy, the catalog of the owner's newest own proposal to
//! that repo, is superseded (Engine 10-22 03:4x): no repo history, folder
//! match or guest field chooses a requirement. A host that binds a catalog
//! of its own makes it an explicit requirement beside any vault policy.

use std::sync::Arc;

use super::RepoReviewPolicy;
use crate::error::Result;
use crate::repo_mutation::proposal::RepoProposalReview;
use crate::{EntityId, Vault};

/// The host's stock [`RepoReviewPolicy`]: every run's proposal is held to
/// the vault's review policy.
pub struct OwnerProposalReviewPolicy {
    vault: Arc<Vault>,
}

impl OwnerProposalReviewPolicy {
    #[must_use]
    pub const fn new(vault: Arc<Vault>) -> Self {
        Self { vault }
    }

    /// The vault it serves.
    #[must_use]
    pub fn vault(&self) -> &Vault {
        &self.vault
    }
}

impl RepoReviewPolicy for OwnerProposalReviewPolicy {
    fn review(&self, _project: EntityId, _repo: EntityId) -> Result<RepoProposalReview> {
        Ok(RepoProposalReview::VaultDefault)
    }
}
