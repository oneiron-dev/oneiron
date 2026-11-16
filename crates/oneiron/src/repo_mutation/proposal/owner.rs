//! The owner proposer: an authenticated owner's ordinary file proposal, its
//! native file bundle proposal and its fresh re-review of a resolved
//! handle-bearing file. All go through the one checked proposer; the owner
//! proof, the repository pointer, the session and the provenance sources are
//! judged again in its writer. The session and the provenance claim are the
//! engine's (`owner_request`): they are bound once the base and the staged
//! bytes are final.
//!
//! FIX 4367: an owner proposal's base is the tree of the exact commit its
//! stored repository pointer names, read from the object store. It is not
//! the live checkout. So the owner can propose at the queue's green while
//! slow checks run and HEAD is ahead of green. A pointer that is not at the
//! current green still fails enqueue. Landing still checks the staged head
//! and the expected bytes; nothing rebases.

use super::owner_request::OwnerRequestAttribution;
use super::resolve_handles::RereviewPrepared;
use super::*;
use crate::git_wire::{GitOid, GitWire};
use crate::repo_mutation::snapshot::RepoPinnedBase;

/// The owner proof a proposal's writer judges, taken from the request
/// before the request moves into the checked proposer: the repository
/// artifact, the session, the provenance sources and the actor. Both
/// owner proposers judge it through one helper.
struct OwnerWriterCheck {
    repository: EntityId,
    repository_ref: RepoRef,
    session: Option<EntityId>,
    sources: [Option<EntityId>; 4],
    actor: Option<EntityId>,
}

impl OwnerWriterCheck {
    fn of(repository: EntityId, request: &RepoMutationRequest) -> Self {
        Self {
            repository,
            repository_ref: request.repo_ref.clone(),
            session: request.session_id,
            sources: [
                request.op_provenance.turn,
                request.op_provenance.activity,
                request.op_provenance.intent,
                request.op_provenance.substrate_ref,
            ],
            actor: request.actor_id,
        }
    }
}

impl Vault {
    /// Owner doors revalidate their proof in the proposal's writer, not in a
    /// separate preflight transaction. Engine admission stays shared. A
    /// `repair_of` source makes the proposal that failed proposal's
    /// replacement, judged in the same writer (FIX 4364). Its base is the
    /// tree of the commit the stored repository pointer names, not the live
    /// checkout (FIX 4367). The engine binds its session and provenance
    /// claim from `attribution` (NO-DOOR CODE-PROPOSAL-ATTRIBUTION).
    pub(crate) fn propose_repo_mutation_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        repository: EntityId,
        request: RepoMutationRequest,
        review: RepoProposalReview,
        repair_of: Option<EntityId>,
        attribution: &OwnerRequestAttribution,
    ) -> Result<RepoProposal> {
        let proposed = self.propose_repo_mutation_as_owner_checked::<std::convert::Infallible>(
            owner,
            repository,
            request,
            review,
            repair_of,
            attribution,
            |_| Ok(Ok(())),
        )?;
        Ok(proposed.unwrap_or_else(|never| match never {}))
    }

    /// The bundle twin of [`Self::propose_repo_mutation_as_owner`]: an
    /// authenticated owner's native file bundle proposal. Its base is the
    /// tree of the commit the stored repository pointer names (FIX 4367),
    /// and the engine binds its session and provenance claim from
    /// `attribution` (NO-DOOR CODE-PROPOSAL-ATTRIBUTION), whose bundle
    /// lineage names every staged path. A bundle repairs nothing.
    pub(crate) fn propose_repo_bundle_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        repository: EntityId,
        mut request: RepoMutationRequest,
        review: RepoProposalReview,
        attribution: &OwnerRequestAttribution,
    ) -> Result<RepoProposal> {
        let base = self.owner_pinned_base(&request.repo_ref)?;
        // The base is pinned and the bundle is final: bind the sources.
        self.attribute_owner_request(owner, attribution, repository, &mut request)?;
        let writer = OwnerWriterCheck::of(repository, &request);
        let proposed = self.propose_repo_bundle_checked::<std::convert::Infallible>(
            request,
            review,
            ProposalBase::Pinned(base),
            None,
            &crate::repo_mutation::bundle::ProvenFiles::new(),
            |txn| {
                self.check_owner_writer_in_txn(txn, owner, &writer)?;
                Ok(Ok(()))
            },
        )?;
        Ok(proposed.unwrap_or_else(|never| match never {}))
    }

    /// The writer check both owner proposers judge: the repository
    /// artifact, the session kind, the provenance sources' presence and
    /// the actor's proof.
    fn check_owner_writer_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &crate::consent::AuthenticatedOwner,
        writer: &OwnerWriterCheck,
    ) -> Result<()> {
        guards::require_repo_artifact_in_txn(self, txn, writer.repository, &writer.repository_ref)?;
        if let Some(session) = writer.session {
            guards::require_entity_kind(self, txn, session, crate::registry::ENTITY_TYPE_SESSION)?;
        }
        for id in writer.sources.into_iter().flatten() {
            if !crate::ports::EntityStoreRead::port_entity_present(&self.store, txn, &id)? {
                return Err(Error::EntityNotFound);
            }
        }
        if Some(owner.revalidate_in_txn(self, txn)?) != writer.actor {
            return Err(invalid("proposal actor is not the authenticated owner"));
        }
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "one owner proposal's proof, repository, request, review, repair source, attribution and check"
    )]
    fn propose_repo_mutation_as_owner_checked<R>(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        repository: EntityId,
        mut request: RepoMutationRequest,
        review: RepoProposalReview,
        repair_of: Option<EntityId>,
        attribution: &OwnerRequestAttribution,
        check: impl FnOnce(&heed::RoTxn<'_>) -> Result<std::result::Result<(), R>>,
    ) -> Result<std::result::Result<RepoProposal, R>> {
        let base = self.owner_pinned_base(&request.repo_ref)?;
        // The base is pinned and the bytes are final: bind the sources.
        self.attribute_owner_request(owner, attribution, repository, &mut request)?;
        let writer = OwnerWriterCheck::of(repository, &request);
        let proposed = self.propose_repo_mutation_checked(
            request,
            review,
            ProposalBase::Pinned(base),
            None,
            Some(owner),
            repair_of,
            |txn| {
                self.check_owner_writer_in_txn(txn, owner, &writer)?;
                check(txn)
            },
        )?;
        Ok(proposed)
    }

    /// The base of an owner proposal (FIX 4367): the tree of the exact
    /// commit the stored repository pointer `pointer` names, read from the
    /// repository's object store under snapshot custody. The live checkout
    /// is not read. The proposal's writer checks that `pointer` is still the
    /// stored pointer, and the checked proposer checks that the captured
    /// head is the request's pin.
    ///
    /// # Errors
    /// A pointer that is not a local repository at a lowercase 40-hex
    /// commit, a commit or tree its object store cannot read, or a store
    /// failure.
    fn owner_pinned_base(&self, pointer: &RepoRef) -> Result<RepoPinnedBase> {
        let repo_root = resolve_mutable_repo_root(pointer)?;
        let canonical = admitted_repo_ref(pointer, &repo_root)?;
        // `admitted_repo_ref` has refused a pointer without a 40-hex commit.
        let commit = GitOid::parse_hex(canonical.commit_hash().unwrap_or_default())?;
        let repo = GitWire::new(self)?.open_repo(canonical, &repo_root)?;
        self.capture_repo_snapshot_at_commit(&repo, &commit)
    }

    pub(crate) fn propose_repo_rereview_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        repository: EntityId,
        original: EntityId,
        mut request: RepoMutationRequest,
        review: RepoProposalReview,
        attribution: &OwnerRequestAttribution,
    ) -> Result<RepoProposal> {
        // The engine's projection replaces the content first, so the
        // attribution binds the bytes that are staged.
        let prepared = RereviewPrepared::new(self, original, &mut request)?;
        let proposed = self.propose_repo_mutation_as_owner_checked::<std::convert::Infallible>(
            owner,
            repository,
            request,
            review,
            None,
            attribution,
            |txn| {
                prepared.revalidate(self, txn)?;
                Ok(Ok(()))
            },
        )?;
        Ok(proposed.unwrap_or_else(|never| match never {}))
    }
}
