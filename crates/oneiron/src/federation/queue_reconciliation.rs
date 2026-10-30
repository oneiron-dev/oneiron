//! The sealed admission of a merge queue reconciliation (FIX 6868, G2 PR2,
//! L02 authority seam).
//!
//! It binds one proven queue overlap (its repository, attached branch,
//! participating batches, two source proposals and shared paths) to the
//! real creator of the reconciliation: the stored actor of the driven
//! batch's source, with the class its host stamped. It is the queue's
//! custody of accepted candidates, never a task-create grant: the TASK's
//! own writer still decides at that creator's current ceiling, and first
//! asks [`QueueReconciliationAdmission::creator_grant_in_txn`] whether the
//! creator's live Grant covers the repository, the branch and every
//! conflicted path (the spec's current repo/branch/path policy, FIX 7308).
//! It has no public constructor, no deserializer and builds no owner
//! credential. An unstamped class reads as a person only for a live vault
//! owner; any other unstamped actor reads as an agent, never promoted.
use super::{RepoAccessRefusal, RepoTarget};
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::merge_queue::QueueStageOverlap;

/// A proven queue overlap's reconciliation and its real creator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QueueReconciliationAdmission {
    repo: EntityId,
    full_ref: String,
    branch_subject: EntityId,
    base_green: String,
    batches: Vec<String>,
    sources: Vec<EntityId>,
    paths: Vec<String>,
    /// `None` when the source's actor was erased: no one to mint for.
    creator: Option<(EntityId, EdgeActorClass)>,
}

impl QueueReconciliationAdmission {
    /// Why a queue reconciliation TASK is held, as its link and the
    /// creator's notice say it.
    pub(crate) const TASK_HELD: &'static str = "the reconciliation task waits: its creator's task \
         authority is below Auto, so the merge queue mints no task in its name; a policy or \
         approval change that admits it lets the queue mint it, and the overlapping work is kept";

    /// Why a queue reconciliation TASK is held when its creator's live
    /// Grant does not cover the repository, the branch and every conflicted
    /// path; the refusal's own message follows it.
    const TASK_GRANT_HELD: &'static str = "the reconciliation task waits: its creator's Grant \
         does not cover this repository, its branch and every conflicted path, so the merge \
         queue mints no task in its name; a Grant that covers them lets the queue mint it, and \
         the overlapping work is kept";

    /// The admission of `overlap`, its creator read from the driven source's
    /// stored proposal.
    ///
    /// # Errors
    /// A source that is no stored proposal of the overlap, or a store failure.
    pub(crate) fn admit(vault: &Vault, overlap: &QueueStageOverlap) -> Result<Self> {
        if !overlap.sources.contains(&overlap.driven_source) {
            return Err(crate::contract_oracle::invalid(
                "the driven source is not one of the overlap's sources",
            ));
        }
        let row = vault
            .repo_proposal(overlap.driven_source)?
            .ok_or(Error::EntityNotFound)?;
        let creator = match row.actor.id() {
            None => None,
            Some(actor) => {
                let class = match row.actor_class.and_then(EdgeActorClass::try_from_u8) {
                    Some(class) => class,
                    None => {
                        let txn = vault.store.env.read_txn()?;
                        if crate::policy_model::is_live_vault_owner_in_txn(vault, &txn, &actor)? {
                            EdgeActorClass::Human
                        } else {
                            EdgeActorClass::Agent
                        }
                    }
                };
                Some((actor, class))
            }
        };
        Ok(Self {
            repo: overlap.repo,
            full_ref: overlap.target.full_ref.clone(),
            branch_subject: overlap.target.branch_subject,
            base_green: overlap.base_green.clone(),
            batches: overlap.batches.clone(),
            sources: overlap.sources.clone(),
            paths: overlap.paths.clone(),
            creator,
        })
    }

    /// Whether this admission still answers `overlap` in `txn`: the same
    /// repository, branch, base, batches, sources and paths, and a creator
    /// whose record is still present.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn holds_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        overlap: &QueueStageOverlap,
    ) -> Result<bool> {
        if self.repo != overlap.repo
            || self.full_ref != overlap.target.full_ref
            || self.branch_subject != overlap.target.branch_subject
            || self.base_green != overlap.base_green
            || self.batches != overlap.batches
            || self.sources != overlap.sources
            || self.paths != overlap.paths
        {
            return Ok(false);
        }
        match self.creator {
            Some((creator, _)) => {
                crate::ports::EntityStoreRead::port_entity_present(&vault.store, txn, &creator)
            }
            None => Ok(true),
        }
    }

    /// The creator the TASK is minted for, and its class.
    pub(crate) fn creator(&self) -> Option<(EntityId, EdgeActorClass)> {
        self.creator
    }

    /// Whether the creator's live Grant covers this reconciliation in the
    /// caller's snapshot `txn`: the repository, the branch's full ref and
    /// every conflicted path, judged for an edit by the same L02 seam the
    /// TASK's own run is admitted through ([`Vault::admit_repo_edit_in_txn`],
    /// called, never copied). A person who is a live vault owner stands on
    /// his own proof, as at his own doors, and no Grant is read; an erased
    /// creator has none to judge. `Ok(Err(_))` is the seam's typed refusal.
    ///
    /// # Errors
    /// A store, fold or clock failure; never a refusal.
    pub(crate) fn creator_grant_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<std::result::Result<(), RepoAccessRefusal>> {
        let Some((creator, class)) = self.creator else {
            return Ok(Ok(()));
        };
        if matches!(class, EdgeActorClass::Human)
            && crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &creator)?
        {
            return Ok(Ok(()));
        }
        let target = RepoTarget {
            repo: self.repo,
            git_ref: self.full_ref.clone(),
            paths: self.paths.clone(),
        };
        Ok(vault
            .admit_repo_edit_in_txn(txn, creator, class, self.repo, &target)?
            .map(drop))
    }

    /// The hold a Grant refusal keeps, as the link and the creator's notice
    /// say it.
    pub(crate) fn grant_held(refused: RepoAccessRefusal) -> String {
        format!("{}: {}", Self::TASK_GRANT_HELD, refused.message())
    }
}
