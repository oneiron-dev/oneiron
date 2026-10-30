//! Code conflict doors: record a conflict and read its history.
//! `Memory::code_conflict_record_as` is its call surface.
//! `memory::code_doors::conflict_types` defines the records these return.

use super::*;
use crate::repo_mutation::RepoConflictClaim;

impl Memory<'_> {
    pub fn code_conflict_record_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeConflictRecordRequest,
    ) -> MemoryResult<CodeConflictView> {
        self.code_owner(owner)?;
        let repo = self.code_repo(input.repo)?;
        for id in [
            input.branch_subject,
            input.left_proposal,
            input.right_proposal,
        ] {
            self.code_readable(id, None)?;
        }
        let id = self.vault.record_repo_proposal_conflict_as_owner(
            owner,
            input.repo,
            &repo,
            input.branch_subject,
            &input.branch,
            [input.left_proposal, input.right_proposal],
        )?;
        let conflict = self
            .vault
            .repo_conflict_claims(&input.branch_subject)?
            .into_iter()
            .find(|row| row.claim_id == id)
            .ok_or_else(|| MemoryError::not_found("recorded conflict is not readable"))?;
        self.code_conflict_view(conflict)
    }

    pub fn code_conflict_history_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeConflictViewRequest,
    ) -> MemoryResult<CodeConflictHistory> {
        self.code_owner(owner)?;
        self.code_readable(input.branch_subject, None)?;
        let conflicts = self
            .vault
            .repo_conflict_claim_history(&input.branch_subject)?
            .into_iter()
            .map(|row| self.code_conflict_view(row))
            .collect::<MemoryResult<Vec<_>>>()?;
        let mut resolved = Vec::new();
        for row in self
            .vault
            .repo_conflict_resolution_claims(&input.branch_subject)?
        {
            self.code_readable(row.claim_id, None)?;
            self.code_readable(row.open_conflict_claim_id, None)?;
            let task = self.code_conflict_task(row.open_conflict_claim_id)?;
            resolved.push(CodeConflictResolutionView {
                resolution: row.claim_id,
                conflict: row.open_conflict_claim_id,
                task,
                resolved_tree: row.resolved_tree,
                paths: row.resolved_paths,
            });
        }
        Ok(CodeConflictHistory {
            conflicts,
            resolved,
        })
    }

    pub(super) fn code_conflict_task(&self, conflict: EntityId) -> MemoryResult<EntityId> {
        let task = self
            .vault
            .repo_reconciliation_task(conflict)?
            .ok_or_else(|| MemoryError::not_found("conflict has no reconciliation task"))?;
        self.code_readable(task, Some(crate::registry::ENTITY_TYPE_TASK))?;
        Ok(task)
    }

    fn code_conflict_view(&self, row: RepoConflictClaim) -> MemoryResult<CodeConflictView> {
        self.code_readable(row.claim_id, None)?;
        for id in &row.proposals {
            self.code_readable(*id, None)?;
        }
        // A held conflict keeps its claim with no TASK and says why (FIX 8830).
        let task = match self.vault.repo_reconciliation_task(row.claim_id)? {
            Some(task) => {
                self.code_readable(task, Some(crate::registry::ENTITY_TYPE_TASK))?;
                Some(task)
            }
            None => None,
        };
        let open = self
            .vault
            .get_claim(&row.claim_id)?
            .is_some_and(|body| body.lifecycle == crate::claim::ClaimLifecycleStatus::Active);
        let held = (task.is_none() && open)
            .then(|| crate::task_verb::REPO_RECONCILIATION_TASK_HELD.to_owned());
        Ok(CodeConflictView {
            open,
            conflict: row.claim_id,
            branch_subject: row.subject,
            repo_ref: row.repo_ref.canonical(),
            branch: row.branch,
            base_tree: row.base_tree,
            left_tree: row.ours_tree,
            right_tree: row.theirs_tree,
            paths: row.conflicted_paths,
            proposals: row.proposals,
            task,
            held,
        })
    }
}
