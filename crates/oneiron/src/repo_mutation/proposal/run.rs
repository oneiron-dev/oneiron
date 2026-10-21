//! A leased run's proposal (FIX 6867, G1 PR2b): the one checked proposer on
//! the immutable base its work is pinned at, with the run's stamp and its
//! actor's class on the row before the row's first write. The actor id stays
//! the proposal's own [`ProposalActor`](super::actor_erase::ProposalActor),
//! erasable as ever; neither the stamp nor the class names or revives one.
//! A private proposal lands no file: review, the merge queue and landing
//! are unchanged.

use super::submit::ProposalBase;
use super::{RepoProposal, RepoProposalReview, invalid};
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::memory::repo_doors::RepoRunStamp;
use crate::repo_mutation::RepoMutationRequest;
use crate::repo_mutation::snapshot::RepoPinnedBase;
use crate::write_envelope::WriteActor;

impl RepoProposal {
    /// The class its actor writes its document edit as: the class a host
    /// stamped on a run's proposal, else the agent class the trusted and
    /// owner ingress has always written.
    ///
    /// # Errors
    /// A stored class byte that names no class.
    pub(crate) fn document_class(&self) -> Result<EdgeActorClass> {
        Ok(self.recorded_class()?.unwrap_or(EdgeActorClass::Agent))
    }

    /// The class it records beside its actor, if a host stamped one.
    ///
    /// # Errors
    /// A stored class byte that names no class.
    pub(super) fn recorded_class(&self) -> Result<Option<EdgeActorClass>> {
        self.actor_class
            .map(|byte| {
                EdgeActorClass::try_from_u8(byte)
                    .ok_or_else(|| invalid("proposal actor class is not a class"))
            })
            .transpose()
    }

    /// The writer its reviewed document edit records: its live actor, at
    /// [`Self::document_class`]. An erased actor writes nothing.
    ///
    /// # Errors
    /// An erased actor or a stored class byte that names no class.
    pub(crate) fn document_actor(&self) -> Result<WriteActor> {
        Ok(WriteActor::new(self.actor.live()?, self.document_class()?))
    }
}

impl Vault {
    /// The stored proposal `id`, read in the caller's snapshot `txn`.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn repo_proposal_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: crate::EntityId,
    ) -> Result<Option<RepoProposal>> {
        super::PROPOSAL.get(&self.store, txn, &id)
    }

    /// A run's proposal: `request` names the host-stamped writer
    /// ([`RepoMutationRequest::with_write_actor`]) and the commit the run's
    /// work is pinned at, `base` is that commit's tree, and `stamp` is the
    /// run's, bound on the row. `check` is the proposal writer's first act,
    /// where the run is judged again; its refusal writes nothing.
    ///
    /// # Errors
    /// A request with no stamped writer, a base that is not the stamp's pin,
    /// or any error of the shared proposer.
    pub(crate) fn propose_repo_mutation_for_run<R>(
        &self,
        request: RepoMutationRequest,
        review: RepoProposalReview,
        base: RepoPinnedBase,
        stamp: RepoRunStamp,
        check: impl FnOnce(&heed::RoTxn<'_>) -> Result<std::result::Result<(), R>>,
    ) -> Result<std::result::Result<RepoProposal, R>> {
        if request.actor_id.is_none() || request.actor_class.is_none() {
            return Err(invalid("a run's proposal names its host-stamped writer"));
        }
        if base.fork_hash != stamp.base_snapshot
            || request.repo_ref.commit_hash() != Some(stamp.base_green.as_str())
        {
            return Err(invalid("a run's proposal base is not its work's pin"));
        }
        self.propose_repo_mutation_checked(
            request,
            review,
            ProposalBase::Pinned(base),
            Some(stamp),
            check,
        )
    }
}
