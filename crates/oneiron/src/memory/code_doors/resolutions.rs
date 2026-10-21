use super::proposals::{fork_hex, owner_submission};
use super::*;
use crate::critic::{CritiqueArtifact, CritiqueProvenance};
use crate::repo_mutation::RepoMutationOperation;
use crate::repo_mutation::proposal::{RepoProposal, RepoProposalOperation};

impl Memory<'_> {
    pub fn code_proposal_resolve_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeProposalResolveRequest,
    ) -> MemoryResult<CodeProposalSubmitted> {
        let actor = self.code_owner(owner)?;
        let repo = self.code_repo(input.change.repo)?;
        self.code_submission_sources(&input.change)?;
        self.code_readable(input.branch_subject, None)?;
        self.code_readable(input.conflict, Some(crate::registry::ENTITY_TYPE_CLAIM))?;
        self.code_conflict_task(input.conflict)?;
        let repo_id = input.change.repo;
        let (mut request, catalog) = owner_submission(repo, actor, input.change);
        let RepoMutationOperation::CommitFile {
            path,
            content,
            message,
        } = request.operation
        else {
            unreachable!("owner_submission constructs a file change");
        };
        request.operation = RepoMutationOperation::ResolveConflictFile {
            branch_subject: input.branch_subject,
            open_conflict_claim_id: input.conflict,
            branch_name: input.branch,
            path,
            content,
            message,
        };
        let row = self
            .vault
            .propose_repo_mutation_as_owner(owner, repo_id, request, catalog)?;
        self.produced_from([row.id]);
        Ok(CodeProposalSubmitted {
            proposal: row.id,
            repo: repo_id,
            actor,
            session: row.session,
            provenance_claim: row.provenance_claim,
            base: fork_hex(&row.pre_action_fork_hash),
            status: row.status,
        })
    }

    pub fn code_proposal_review_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeProposalReviewRequest,
    ) -> MemoryResult<CodeProposalSettlementView> {
        let actor = self.code_owner(owner)?;
        self.code_readable(input.proposal, None)?;
        for id in &input.evidence {
            self.code_readable(*id, None)?;
        }
        self.code_readable(input.calibration.subject, None)?;
        let row = self
            .vault
            .repo_proposal(input.proposal)?
            .ok_or_else(|| MemoryError::not_found("repository proposal not found"))?;
        let lens = row
            .catalog
            .lens(&input.lens_id, &input.domain)
            .ok_or_else(|| {
                MemoryError::bad_request("review lens is not in this proposal's catalog")
            })?;
        let critique = CritiqueArtifact::new(
            input.artifact_id,
            input.run_id,
            crate::attempt_queue::AttemptId::from_bytes(input.attempt.as_bytes())?,
            row.id.to_hex(),
            lens,
            CritiqueProvenance::new(
                crate::write_envelope::WriteActor::new(actor, self.actor_class),
                input.model_id,
                input.model_revision,
            )?,
            input.calibration,
            input.verdict,
            input.severity,
            input.hard_check_passed,
            input.evidence.iter().map(EntityId::to_hex).collect(),
            input.suggested_edit,
            self.vault.now_recorded_at(),
        )?;
        let row = self
            .vault
            .review_repo_proposal_as_owner(owner, row.id, critique)?;
        self.code_settlement_view(row)
    }

    pub fn code_proposal_settle_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeProposalSettleRequest,
    ) -> MemoryResult<CodeProposalSettlementView> {
        self.code_owner(owner)?;
        self.code_readable(input.proposal, None)?;
        let row =
            self.vault
                .settle_repo_proposal_as_owner(owner, input.proposal, input.decision)?;
        self.code_settlement_view(row)
    }

    pub fn code_proposal_settlement_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeProposalSettlementRequest,
    ) -> MemoryResult<CodeProposalSettlementView> {
        self.code_owner(owner)?;
        self.code_readable(input.proposal, None)?;
        let row = self
            .vault
            .repo_proposal(input.proposal)?
            .ok_or_else(|| MemoryError::not_found("repository proposal not found"))?;
        self.code_settlement_view(row)
    }

    fn code_settlement_view(&self, row: RepoProposal) -> MemoryResult<CodeProposalSettlementView> {
        self.code_listed(
            [
                Some(row.id),
                row.actor.id(),
                Some(row.session),
                Some(row.provenance_claim),
            ]
            .into_iter()
            .flatten(),
        )?;
        if let Some(settled) = &row.settlement {
            self.code_readable(settled.receipt, None)?;
        }
        let (conflict, task, parents, resolution) = match &row.operation {
            RepoProposalOperation::CommitFile | RepoProposalOperation::ReceivedFiles { .. } => {
                (None, None, Vec::new(), None)
            }
            RepoProposalOperation::ResolveConflictFile {
                branch_subject,
                open_conflict_claim_id,
                ..
            } => {
                self.code_readable(*open_conflict_claim_id, None)?;
                let task = self.code_conflict_task(*open_conflict_claim_id)?;
                let body = self
                    .vault
                    .get_claim(open_conflict_claim_id)?
                    .ok_or_else(|| MemoryError::not_found("conflict claim not found"))?;
                let value = crate::repo_mutation::conflict_proposals(&body)?;
                for id in &value {
                    self.code_readable(*id, None)?;
                }
                let resolution =
                    if row.status == crate::repo_mutation::proposal::RepoProposalStatus::Applied {
                        self.vault
                            .repo_conflict_resolution_claims(branch_subject)?
                            .into_iter()
                            .find(|claim| claim.open_conflict_claim_id == *open_conflict_claim_id)
                            .map(|claim| claim.claim_id)
                    } else {
                        None
                    };
                if let Some(id) = resolution {
                    self.code_readable(id, None)?;
                }
                (Some(*open_conflict_claim_id), Some(task), value, resolution)
            }
        };
        Ok(CodeProposalSettlementView {
            proposal: row.id,
            status: row.status,
            reviews: row.critiques.len(),
            settlement: row.settlement,
            conflict,
            task,
            parents,
            mutation_seq: row.operation_seq,
            resolution,
        })
    }
}
