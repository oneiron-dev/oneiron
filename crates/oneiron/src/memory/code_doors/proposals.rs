//! Code proposal submission and the repository mutation log read.
//! `Memory::code_proposal_submit_as` and `owner_submission` are its call surface.
//! `memory::code_doors::types` defines the records these take and return.

use super::*;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::repo_mutation::proposal::{OwnerRequestAttribution, RepoProposal, RepoProposalReview};
use crate::store::repo_fork::RepoForkHash;
use crate::{
    repo_mutation::RepoMutationRequest,
    store::repo_mutation_record::RepoMutationStatus,
    store::repo_mutation_record::{RepoMutationOperation, RepoMutationOplogEntry},
};

impl Memory<'_> {
    /// `vault.code.proposal_submit`: stages one ordinary file change as a
    /// Proposed repository proposal through the unchanged engine admission,
    /// which captures and retains the base at the pinned commit. The engine
    /// mints the proposal id; nothing is approved, queued, applied or retried.
    /// The answer names its submission admission receipt (FIX 4338); a
    /// `repair_of` source is linked to it as that failed proposal's
    /// replacement in the same writer (FIX 4364). Its session and
    /// provenance claim are the engine's (NO-DOOR CODE-PROPOSAL-ATTRIBUTION).
    pub fn code_proposal_submit_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeProposalSubmitRequest,
    ) -> MemoryResult<CodeProposalSubmitted> {
        let attribution = OwnerRequestAttribution::new("vault.code.proposal_submit", &input)?;
        self.code_proposal_submit(owner, input, None, &attribution)
    }

    /// Submits a fresh review of an approved ordinary file's proved redacted
    /// resolution. The existing input supplies the message and review
    /// policy; its content is replaced by the engine's projection, which the
    /// engine's attribution binds.
    pub fn code_proposal_rereview_as(
        &self,
        owner: &AuthenticatedOwner,
        original: EntityId,
        input: CodeProposalSubmitRequest,
    ) -> MemoryResult<CodeProposalSubmitted> {
        let attribution = OwnerRequestAttribution::new(
            "vault.code.proposal_rereview",
            &CodeProposalRereviewRequest {
                original,
                change: input.clone(),
            },
        )?;
        self.code_proposal_submit(owner, input, Some(original), &attribution)
    }

    fn code_proposal_submit(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeProposalSubmitRequest,
        original: Option<EntityId>,
        attribution: &OwnerRequestAttribution,
    ) -> MemoryResult<CodeProposalSubmitted> {
        let actor = self.code_owner(owner)?;
        let repo_ref = self.code_repo(input.repo)?;
        self.code_submission_sources(&input)?;
        if let Some(original) = original {
            self.code_readable(original, None)?;
        }
        let repo = input.repo;
        let repair_of = input.repair_of;
        let (request, catalog) = owner_submission(repo_ref, actor, input);
        // A re-review keeps its original's lineage: it repairs nothing
        // (FIX 4364).
        if original.is_some() && repair_of.is_some() {
            return Err(MemoryError::bad_request(
                "a re-review cannot also repair a failed proposal",
            ));
        }
        let proposal = match original {
            Some(original) => self.vault.propose_repo_rereview_as_owner(
                owner,
                repo,
                original,
                request,
                catalog,
                attribution,
            )?,
            None => self.vault.propose_repo_mutation_as_owner(
                owner,
                repo,
                request,
                catalog,
                repair_of,
                attribution,
            )?,
        };
        self.code_submitted(repo, actor, &proposal)
    }

    /// A stored proposal's submission answer, with its submission admission
    /// receipt read and checked (FIX 4338), then read through the caller.
    pub(super) fn code_submitted(
        &self,
        repo: EntityId,
        actor: EntityId,
        proposal: &RepoProposal,
    ) -> MemoryResult<CodeProposalSubmitted> {
        self.produced_from([proposal.id]);
        let admission_receipt = self
            .vault
            .repo_proposal_admission_receipt(proposal)?
            .ok_or(crate::error::Error::CorruptedIndex(
                "a stored proposal has no admission receipt",
            ))?;
        self.code_readable(admission_receipt, Some(ENTITY_TYPE_CLAIM))?;
        Ok(CodeProposalSubmitted {
            proposal: proposal.id,
            admission_receipt,
            repo,
            actor,
            session: proposal.session,
            provenance_claim: proposal.provenance_claim,
            base: fork_hex(&proposal.pre_action_fork_hash),
            status: proposal.status,
        })
    }

    /// `vault.code.oplog`: the durable mutation log of one repository, in
    /// sequence order, as the engine recorded it. A read only: no recovery,
    /// polling or dependency is computed, and a pending proposal is absent.
    pub fn code_mutation_log_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeRepoRequest,
    ) -> MemoryResult<CodeMutationLog> {
        self.code_owner(owner)?;
        let repo_ref = self.code_repo(input.repo)?;
        let entries = self.vault.repo_mutation_oplog(&repo_ref)?;
        self.code_listed(
            entries
                .iter()
                .flat_map(|entry| [entry.actor_id, entry.session_id])
                .flatten(),
        )?;
        Ok(CodeMutationLog {
            repo: input.repo,
            entries: entries.into_iter().map(mutation_entry).collect(),
        })
    }

    /// The CALL behind proposal provenance: every operation provenance ref
    /// present read through the caller's credential. The session and the
    /// `repo.provenance` claim are the engine's, bound in the proposal's
    /// writer; the actor is the caller. A repair source is a proposal the
    /// caller reads too (FIX 4364); the engine judges its failure in the
    /// replacement's writer.
    pub(super) fn code_submission_sources(
        &self,
        input: &CodeProposalSubmitRequest,
    ) -> MemoryResult<()> {
        if let Some(source) = input.repair_of {
            self.code_readable(source, Some(ENTITY_TYPE_CLAIM))?;
        }
        let provenance = &input.op_provenance;
        for id in [
            provenance.turn,
            provenance.activity,
            provenance.intent,
            provenance.substrate_ref,
        ]
        .into_iter()
        .flatten()
        {
            self.code_readable(id, None)?;
        }
        Ok(())
    }
}

/// The CALL behind proposal admission policy: the engine request stamps the
/// caller as actor, and the review is the explicit typed catalog the owner
/// sent with this proposal, or with none the vault's review policy (FIX
/// 8268). No built seed stands in for it and an agent never picks it; the
/// engine validates a sent catalog at admission. The request names no
/// session or provenance claim: the owner writer binds them.
pub(super) fn owner_submission(
    repo_ref: RepoRef,
    actor: EntityId,
    input: CodeProposalSubmitRequest,
) -> (RepoMutationRequest, RepoProposalReview) {
    let request = RepoMutationRequest::new(
        repo_ref,
        RepoMutationOperation::CommitFile {
            path: input.path,
            content: input.content,
            message: input.message,
        },
    )
    .with_actor_id(actor)
    .with_op_provenance(input.op_provenance);
    let review = input.catalog.map_or(
        RepoProposalReview::VaultDefault,
        RepoProposalReview::Explicit,
    );
    (request, review)
}

/// The CALL behind oplog states: an entry keeps the engine's own prepared,
/// applied or failed state. It is never relabeled waiting, running or landed.
fn mutation_entry(entry: RepoMutationOplogEntry) -> CodeMutationEntry {
    CodeMutationEntry {
        repo_ref: entry.repo_ref.canonical(),
        seq: entry.seq,
        operation_kind: entry.operation_kind,
        operation_subject: entry.operation_subject,
        actor: entry.actor_id,
        session: entry.session_id,
        started_at_ms: entry.started_at_ms,
        finished_at_ms: entry.finished_at_ms,
        pre_action_fork_hash: fork_hex(&entry.pre_action_fork_hash),
        expected_post_action_fork_hash: entry.expected_post_action_fork_hash.as_ref().map(fork_hex),
        status: match entry.status {
            RepoMutationStatus::Prepared => CodeMutationState::Prepared,
            RepoMutationStatus::Applied => CodeMutationState::Applied,
            RepoMutationStatus::Failed => CodeMutationState::Failed,
        },
        failure: entry.failure,
    }
}

/// A BLAKE3 fork hash as 64 lower-hex characters.
pub(super) fn fork_hex(hash: &RepoForkHash) -> String {
    blake3::Hash::from_bytes(*hash).to_hex().to_string()
}
