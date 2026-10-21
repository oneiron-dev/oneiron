//! The sealed admission of a merge queue reconciliation (FIX 6868, G2 PR2,
//! L02 authority seam).
//!
//! It binds one proven queue overlap (its repository, attached branch,
//! participating batches, two source proposals and shared paths) to the
//! real creator of the reconciliation: the stored actor of the driven
//! batch's source, with the class its host stamped. It is the queue's
//! custody of accepted candidates, never a task-create grant: the TASK's
//! own writer still decides at that creator's current ceiling. It has no
//! public constructor, no deserializer and builds no owner credential. An
//! unstamped class reads as a person only for a live vault owner; any other
//! unstamped actor reads as an agent, never promoted.
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
}
