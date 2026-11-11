//! The repo secret purge doors (FIX 7608 slice 10, owner ruling
//! SECRETS-IN-REPOS = A): `vault.code.secrets.purge.request` plans the
//! purge of marked keys from one served repository's history and shows
//! what it affects, `vault.code.secrets.purge.get` reads a plan and its
//! receipt, and `vault.code.secrets.purge.execute` is the owner's
//! confirmation of one plan. Owner-only, as every origin door is
//! (`Memory::origin_owner`); a plan is read and executed only by the owner
//! who made it. No door reads, returns or logs a value, span or excerpt.

use super::*;
use crate::origin::secret_purge::{
    RepoSecretPurgeIdRequest, RepoSecretPurgePlan, RepoSecretPurgeReceipt, RepoSecretPurgeRequest,
    RepoSecretPurgeView,
};

impl Memory<'_> {
    /// `vault.code.secrets.purge.request`: plans the purge and freezes it;
    /// no ref moves.
    pub fn code_secrets_purge_request_as(
        &self,
        owner: &AuthenticatedOwner,
        input: RepoSecretPurgeRequest,
    ) -> MemoryResult<RepoSecretPurgePlan> {
        self.origin_owner(owner)?;
        Ok(self.vault.plan_repo_secret_purge(owner, &input)?)
    }

    /// `vault.code.secrets.purge.get`: one plan of this owner's, and its
    /// receipt once executed.
    pub fn code_secrets_purge_get_as(
        &self,
        owner: &AuthenticatedOwner,
        input: RepoSecretPurgeIdRequest,
    ) -> MemoryResult<RepoSecretPurgeView> {
        let actor = self.origin_owner(owner)?;
        self.owned_purge(actor, input.plan)
    }

    /// `vault.code.secrets.purge.execute`: runs this owner's plan, under
    /// this host's origin authority lease when it holds one, and answers
    /// its receipt. A plan with a receipt answers that receipt.
    pub fn code_secrets_purge_execute_as(
        &self,
        owner: &AuthenticatedOwner,
        input: RepoSecretPurgeIdRequest,
    ) -> MemoryResult<RepoSecretPurgeReceipt> {
        let actor = self.origin_owner(owner)?;
        let view = self.owned_purge(actor, input.plan)?;
        if let Some(receipt) = view.receipt {
            return Ok(receipt);
        }
        let authority = self.origin_export_authority(&view.plan.repo)?;
        Ok(self
            .vault
            .execute_repo_secret_purge(owner, input.plan, authority.as_ref())?)
    }

    /// The plan `plan` when `actor` made it; another owner's plan is not
    /// found.
    fn owned_purge(&self, actor: EntityId, plan: EntityId) -> MemoryResult<RepoSecretPurgeView> {
        match self.vault.repo_secret_purge(plan)? {
            Some(view) if view.plan.owner == actor => Ok(view),
            _ => Err(MemoryError::not_found("repo secret purge plan not found")),
        }
    }
}
