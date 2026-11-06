//! The owner proposer: an authenticated owner's ordinary file proposal and
//! its fresh re-review of a resolved handle-bearing file. Both go through
//! the one checked proposer; the owner proof, the repository pointer, the
//! session and the provenance sources are judged again in its writer.

use super::resolve_handles::RereviewPrepared;
use super::*;

impl Vault {
    /// Owner doors revalidate their proof in the proposal's writer, not in a
    /// separate preflight transaction. Engine admission stays shared. A
    /// `repair_of` source makes the proposal that failed proposal's
    /// replacement, judged in the same writer (FIX 4364).
    pub(crate) fn propose_repo_mutation_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        repository: EntityId,
        request: RepoMutationRequest,
        review: RepoProposalReview,
        repair_of: Option<EntityId>,
    ) -> Result<RepoProposal> {
        let proposed = self.propose_repo_mutation_as_owner_checked::<std::convert::Infallible>(
            owner,
            repository,
            request,
            review,
            repair_of,
            |_| Ok(Ok(())),
        )?;
        Ok(proposed.unwrap_or_else(|never| match never {}))
    }

    fn propose_repo_mutation_as_owner_checked<R>(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        repository: EntityId,
        request: RepoMutationRequest,
        review: RepoProposalReview,
        repair_of: Option<EntityId>,
        check: impl FnOnce(&heed::RoTxn<'_>) -> Result<std::result::Result<(), R>>,
    ) -> Result<std::result::Result<RepoProposal, R>> {
        let actor = request.actor_id;
        let repository_ref = request.repo_ref.clone();
        let session = request.session_id;
        let sources = [
            request.op_provenance.turn,
            request.op_provenance.activity,
            request.op_provenance.intent,
            request.op_provenance.substrate_ref,
        ];
        let proposed = self.propose_repo_mutation_checked(
            request,
            review,
            ProposalBase::CurrentCheckout,
            None,
            Some(owner),
            repair_of,
            |txn| {
                guards::require_repo_artifact_in_txn(self, txn, repository, &repository_ref)?;
                if let Some(session) = session {
                    guards::require_entity_kind(
                        self,
                        txn,
                        session,
                        crate::registry::ENTITY_TYPE_SESSION,
                    )?;
                }
                for id in sources.into_iter().flatten() {
                    if !crate::ports::EntityStoreRead::port_entity_present(&self.store, txn, &id)? {
                        return Err(Error::EntityNotFound);
                    }
                }
                if Some(owner.revalidate_in_txn(self, txn)?) != actor {
                    return Err(invalid("proposal actor is not the authenticated owner"));
                }
                check(txn)
            },
        )?;
        Ok(proposed)
    }

    pub(crate) fn propose_repo_rereview_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        repository: EntityId,
        original: EntityId,
        mut request: RepoMutationRequest,
        review: RepoProposalReview,
    ) -> Result<RepoProposal> {
        let prepared = RereviewPrepared::new(self, original, &mut request)?;
        let proposed = self.propose_repo_mutation_as_owner_checked::<std::convert::Infallible>(
            owner,
            repository,
            request,
            review,
            None,
            |txn| {
                prepared.revalidate(self, txn)?;
                Ok(Ok(()))
            },
        )?;
        Ok(proposed.unwrap_or_else(|never| match never {}))
    }
}
