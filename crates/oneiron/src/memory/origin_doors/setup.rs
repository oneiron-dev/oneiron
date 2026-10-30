//! The owner's repository registration and outbound mirror setup, through the
//! same proof and credential-scoped handle as the origin authority doors.

use super::*;
use crate::origin::mirror::{OriginMirrorRun, OriginMirrorTarget, OriginMirrorTargetInput};
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

    pub fn origin_mirror_set_as(
        &self,
        owner: &AuthenticatedOwner,
        input: OriginMirrorSetRequest,
    ) -> MemoryResult<OriginMirrorTarget> {
        let mut txn = self.vault.store.env.write_txn()?;
        self.origin_owner_in_txn(owner, &txn)?;
        let mirror = self.vault.set_served_origin_mirror_in_txn(
            &mut txn,
            &input.repo,
            OriginMirrorTargetInput {
                url: input.url,
                secret_ref: input.secret_ref,
                user: input.user,
                every_secs: input.every_secs,
                sync_strategy: input.sync_strategy,
                visibility: input.visibility,
            },
        )?;
        txn.commit().map_err(crate::Error::from)?;
        // Committed first: a full-auto mirror plans its published state now.
        self.vault.wake_origin_mirrors();
        Ok(mirror)
    }

    /// Sets the mirror's sync strategy (FIX 6866): the strategy and its
    /// revision only, under the same owner proof as mirror setup.
    pub fn origin_mirror_strategy_as(
        &self,
        owner: &AuthenticatedOwner,
        input: OriginMirrorStrategyRequest,
    ) -> MemoryResult<OriginMirrorTarget> {
        let mut txn = self.vault.store.env.write_txn()?;
        self.origin_owner_in_txn(owner, &txn)?;
        let mirror = self.vault.set_served_origin_mirror_strategy_in_txn(
            &mut txn,
            &input.repo,
            input.sync_strategy,
        )?;
        txn.commit().map_err(crate::Error::from)?;
        self.vault.wake_origin_mirrors();
        Ok(mirror)
    }

    pub fn origin_mirror_clear_as(
        &self,
        owner: &AuthenticatedOwner,
        input: OriginRepoRequest,
    ) -> MemoryResult<OriginMirrorCleared> {
        let mut txn = self.vault.store.env.write_txn()?;
        self.origin_owner_in_txn(owner, &txn)?;
        let cleared = self
            .vault
            .clear_served_origin_mirror_in_txn(&mut txn, &input.repo)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(OriginMirrorCleared {
            repo: input.repo,
            cleared,
        })
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
