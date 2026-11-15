//! The owner's repository registration and outbound mirror reads and pushes,
//! through the same proof and credential-scoped handle as the origin authority
//! doors. The mirror's setup is the catalogue key `origin.mirror`, set through
//! `vault.settings.set` at the repository's scope.

use super::*;
use crate::origin::mirror::OriginMirrorRun;
use crate::origin::publish::{OriginMirrorPlanRequest, OriginMirrorPlanView};

impl Memory<'_> {
    pub fn origin_register_as(
        &self,
        owner: &AuthenticatedOwner,
        input: OriginRegisterRequest,
    ) -> MemoryResult<OriginRegistered> {
        self.origin_owner(owner)?;
        let repo_id = self.vault.register_served_origin_as_owner(
            owner,
            &input.repo,
            &input.default_branch,
        )?;
        Ok(OriginRegistered {
            repo: input.repo,
            repo_id,
            default_branch: input.default_branch,
        })
    }

    pub fn origin_mirror_get_as(
        &self,
        owner: &AuthenticatedOwner,
        input: OriginRepoRequest,
    ) -> MemoryResult<OriginMirrorView> {
        self.origin_owner(owner)?;
        Ok(OriginMirrorView {
            mirror: self.vault.served_origin_mirror(&input.repo)?,
            repo: input.repo,
        })
    }

    /// One automatic push plan of the mirror, with each ref's outcome and
    /// one page of its review (FIX 7175), as the owner.
    pub fn origin_mirror_plan_as(
        &self,
        owner: &AuthenticatedOwner,
        input: OriginMirrorPlanRequest,
    ) -> MemoryResult<OriginMirrorPlanView> {
        self.origin_owner(owner)?;
        Ok(self.vault.origin_mirror_plan(input)?)
    }

    pub fn origin_mirror_push_as(
        &self,
        owner: &AuthenticatedOwner,
        input: OriginRepoRequest,
    ) -> MemoryResult<OriginMirrorRun> {
        self.origin_owner(owner)?;
        Ok(self
            .vault
            .push_served_origin_mirror_as_owner(owner, &input.repo)?)
    }
}
