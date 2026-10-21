//! The one checked proposer (moved from `proposal.rs`, FIX 6867 G1 PR2b):
//! the trusted and owner proposals take their base from the current
//! checkout, a run's from the immutable commit its work is pinned at
//! (PREMISE 3), and both are validated, kept under custody and written by
//! the same code. No proposal lands a file here.

use super::*;
use crate::memory::repo_doors::RepoRunStamp;
use crate::repo_mutation::snapshot::RepoPinnedBase;

/// Where a proposal's pre-action base comes from.
pub(in crate::repo_mutation) enum ProposalBase {
    /// The trusted and owner proposer: the live checkout, captured under the
    /// repo lock, whose HEAD must be the request's pinned commit.
    CurrentCheckout,
    /// A run's proposal: the tree of the commit its work is pinned at, read
    /// from the object store; that commit must be the request's pin.
    Pinned(RepoPinnedBase),
}

impl Vault {
    /// The one checked proposer: validates the request, takes the base,
    /// keeps custody, then writes the journal claims, the base snapshot and
    /// the proposal in one transaction whose first act is `check`. A
    /// refusal there writes nothing. A run's stamp and class are on the row
    /// before that write; the trusted and owner proposer write none.
    pub(in crate::repo_mutation) fn propose_repo_mutation_checked<R>(
        &self,
        request: RepoMutationRequest,
        catalog: LensCatalog,
        base: ProposalBase,
        run: Option<RepoRunStamp>,
        check: impl FnOnce(&heed::RoTxn<'_>) -> Result<std::result::Result<(), R>>,
    ) -> Result<std::result::Result<RepoProposal, R>> {
        validate_operation(&request.operation)?;
        crate::repo_mutation::trailer::validate_repo_provenance_request(self, &request)?;
        let (Some(actor), Some(session), Some(provenance_claim)) = (
            request.actor_id,
            request.session_id,
            request.provenance_claim_id,
        ) else {
            return Err(invalid(
                "code proposal requires actor, session and provenance",
            ));
        };
        request.op_provenance.validate()?;
        let op_provenance = request.op_provenance.clone();
        let request_class = request.actor_class;
        let (path, content, message, operation) = match request.operation {
            RepoMutationOperation::CommitFile {
                path,
                content,
                message,
            } => (path, content, message, RepoProposalOperation::CommitFile),
            RepoMutationOperation::ResolveConflictFile {
                branch_subject,
                open_conflict_claim_id,
                branch_name,
                path,
                content,
                message,
            } => (
                path,
                content,
                message,
                RepoProposalOperation::ResolveConflictFile {
                    branch_subject,
                    open_conflict_claim_id,
                    branch_name,
                },
            ),
            _ => return Err(invalid("code proposal supports one file operation")),
        };
        if content.len() > 32 * 1024 * 1024 || catalog.lenses.is_empty() {
            return Err(invalid(
                "proposal requires bounded content and review lenses",
            ));
        }
        // Empty triage validates the host's catalog without inventing a verdict.
        triage_critiques(&catalog, &[], &[])?;
        let repo_root = resolve_mutable_repo_root(&request.repo_ref)?;
        let repo = admitted_repo_ref(&request.repo_ref, &repo_root)?;
        let _guard = lock_repository(&git_common_dir(&repo_root)?)?;
        self.recover_prepared_repo_mutations_locked(&repo, &repo_root)?;
        let (fork, snapshot) = match base {
            ProposalBase::CurrentCheckout => capture_repo_snapshot(self, &repo_root)?,
            ProposalBase::Pinned(pinned) => (pinned.fork_hash, pinned.encoded),
        };
        let pre_action = crate::repo_mutation::snapshot::decode_snapshot(&snapshot)?;
        require_pinned_head(&repo, pre_action.head.as_deref())?;
        admit_custody(
            &SnapshotCustody::of(self, &repo_root)?,
            &pre_action,
            &path,
            &content,
            &message,
        )?;
        let row = RepoProposal {
            id: EntityId::now(),
            repo: repo.canonical(),
            actor: actor_erase::ProposalActor::Actor(actor),
            session,
            provenance_claim,
            op_provenance,
            files: vec![RepoProposedFile::ordinary(path, content)],
            message,
            operation,
            merge_stack: None,
            pre_action_fork_hash: fork,
            catalog,
            critiques: Vec::new(),
            status: RepoProposalStatus::Proposed,
            settlement: None,
            operation_seq: None,
            created_at: now_millis() / 1000,
            run,
            actor_class: request_class.map(|class| class as u8),
        };
        validate_conflict(self, &row, &repo_root)?;
        let prepared = super::persist::PreparedRepoProposal::new(row, snapshot)?;
        let mut txn = self.store.env.write_txn()?;
        if let Err(refused) = check(&txn)? {
            return Ok(Err(refused));
        }
        prepared.persist_in_txn(self, &mut txn)?;
        txn.commit()?;
        Ok(Ok(prepared.row))
    }
}
