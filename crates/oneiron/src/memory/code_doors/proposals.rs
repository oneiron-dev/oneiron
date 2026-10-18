use super::*;
use crate::critic::LensCatalog;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SESSION};
use crate::repo_mutation::{
    RepoForkHash, RepoMutationOperation, RepoMutationOplogEntry, RepoMutationRequest,
    RepoMutationStatus,
};

impl Memory<'_> {
    /// `vault.code.proposal_submit`: stages one ordinary file change as a
    /// Proposed repository proposal through the unchanged engine admission,
    /// which captures and retains the base at the pinned commit. The engine
    /// mints the proposal id; nothing is approved, queued, applied or retried.
    pub fn code_proposal_submit_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeProposalSubmitRequest,
    ) -> MemoryResult<CodeProposalSubmitted> {
        let actor = self.code_owner(owner)?;
        let repo_ref = self.code_repo(input.repo)?;
        self.code_submission_sources(&input)?;
        let repo = input.repo;
        let (request, catalog) = owner_submission(repo_ref, actor, input);
        let proposal = self
            .vault
            .propose_repo_mutation_as_owner(owner, repo, request, catalog)?;
        self.produced_from([proposal.id]);
        Ok(CodeProposalSubmitted {
            proposal: proposal.id,
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

    /// The CALL behind proposal provenance: an existing SESSION and an
    /// existing `repo.provenance` CLAIM, each read through the caller's
    /// credential, and every provenance ref present read likewise. They are
    /// attribution only; the actor is the caller.
    pub(super) fn code_submission_sources(
        &self,
        input: &CodeProposalSubmitRequest,
    ) -> MemoryResult<()> {
        self.code_readable(input.session, Some(ENTITY_TYPE_SESSION))?;
        self.code_readable(input.provenance_claim, Some(ENTITY_TYPE_CLAIM))?;
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
/// caller as actor, and the review catalog is the explicit typed one the owner
/// sent with this proposal. No built seed stands in for it and an agent never
/// picks it; the engine validates it at admission.
pub(super) fn owner_submission(
    repo_ref: RepoRef,
    actor: EntityId,
    input: CodeProposalSubmitRequest,
) -> (RepoMutationRequest, LensCatalog) {
    let request = RepoMutationRequest::new(
        repo_ref,
        RepoMutationOperation::CommitFile {
            path: input.path,
            content: input.content,
            message: input.message,
        },
    )
    .with_actor_id(actor)
    .with_session_id(input.session)
    .with_provenance_claim_id(input.provenance_claim)
    .with_op_provenance(input.op_provenance);
    (request, input.catalog)
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
