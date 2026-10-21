//! The stock review policy a host binds for runs' proposals (FIX 6867, G1
//! PR3b; closes FIX 7062).
//!
//! The owner's own proposal doors take their review catalog explicitly
//! with each proposal (`vault.code.proposal_submit`, its `catalog` field;
//! `memory/code_doors/proposals.rs` `owner_submission`), and the stored
//! proposal keeps it (`RepoProposal::catalog`). No other per-PROJECT
//! catalog is stored. So a run's proposal to a repo is reviewed under the
//! catalog of the newest proposal the vault's live owner made himself, at
//! his own door, to that repo ([`owner_review_catalog`], CALL "FIX 6867
//! stock review policy"). A repo he never proposed to has no catalog, and
//! the run's proposal keeps today's typed `repo_review_policy_required`
//! hold. No built seed stands in, and no guest field reaches it.

use std::sync::Arc;

use super::RepoReviewPolicy;
use crate::critic::LensCatalog;
use crate::error::Result;
use crate::federation::GitPushRepo;
use crate::{EntityId, Vault};

/// The host's stock [`RepoReviewPolicy`]: [`owner_review_catalog`] over
/// the vault it serves.
pub struct OwnerProposalReviewPolicy {
    vault: Arc<Vault>,
}

impl OwnerProposalReviewPolicy {
    #[must_use]
    pub const fn new(vault: Arc<Vault>) -> Self {
        Self { vault }
    }
}

impl RepoReviewPolicy for OwnerProposalReviewPolicy {
    fn review_catalog(&self, project: EntityId, repo: EntityId) -> Option<LensCatalog> {
        owner_review_catalog(&self.vault, project, repo).unwrap_or_else(|error| {
            // A read that fails binds no catalog: the proposal holds, as with
            // no policy, and the work is kept.
            tracing::warn!(
                kind = ?error.kind(),
                "repo review policy: the owner's catalog did not read; the proposal holds"
            );
            None
        })
    }
}

/// The CALL "FIX 6867 stock review policy": the catalog of the newest
/// proposal (by id) a live owner of this vault made himself, at his own
/// door (no run stamp and no host-stamped class), to the folder the CODE
/// anchor `repo` of `project` stores. `None` when he made none, or when the
/// anchor no longer resolves in its PROJECT.
///
/// # Errors
/// A store or fold failure.
pub fn owner_review_catalog(
    vault: &Vault,
    project: EntityId,
    repo: EntityId,
) -> Result<Option<LensCatalog>> {
    let txn = vault.store.env.read_txn()?;
    let Some(folder) = vault.git_push_anchor_in_txn(&txn, &GitPushRepo { repo, project })? else {
        return Ok(None);
    };
    let owners = crate::policy_model::owners_in_txn(vault, &txn)?;
    vault.owner_review_catalog_in_txn(&txn, &owners, &folder)
}
