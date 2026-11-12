//! `vault.code.origin.lfs_path_policy.get` and `.set` (NO-DOOR
//! REPO-LFS-PATH-POLICY; Engine CODECUSTODY-LFS Q1 = A): the owner reads and
//! replaces one served origin's ordered LFS path rules, under the owner's own
//! proof, as origin setup is. The set names the revision it read; a policy
//! that moved since is refused and nothing is written.

use super::*;
use crate::origin::lfs::{LfsAssetClass, OriginLfsPathPolicy, validate_origin_lfs_path_rules};

impl Memory<'_> {
    pub fn origin_lfs_path_policy_get_as(
        &self,
        owner: &AuthenticatedOwner,
        input: OriginRepoRequest,
    ) -> MemoryResult<OriginLfsPathPolicyView> {
        self.origin_owner(owner)?;
        let (repo_id, policy) = self.vault.served_origin_lfs_path_policy(&input.repo)?;
        Ok(lfs_path_policy_view(input.repo, repo_id, policy))
    }

    pub fn origin_lfs_path_policy_set_as(
        &self,
        owner: &AuthenticatedOwner,
        input: OriginLfsPathPolicySetRequest,
    ) -> MemoryResult<OriginLfsPathPolicyView> {
        self.origin_owner(owner)?;
        validate_origin_lfs_path_rules(&input.rules).map_err(|error| {
            MemoryError::bad_request(format!("an LFS path rule is invalid: {error}"))
        })?;
        let (repo_id, _) = self.vault.served_origin_lfs_path_policy(&input.repo)?;
        let mut txn = self.vault.store.env.write_txn()?;
        self.origin_owner_in_txn(owner, &txn)?;
        let policy = self
            .vault
            .set_origin_lfs_path_policy_in_txn(
                &mut txn,
                repo_id,
                input.expected_revision,
                input.rules,
            )?
            .map_err(|stored| {
                MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    format!(
                        "the LFS path policy is at revision {stored}, not {}",
                        input.expected_revision
                    ),
                    &["Read the policy again and set it at its current revision."],
                )
            })?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(lfs_path_policy_view(input.repo, repo_id, policy))
    }
}

fn lfs_path_policy_view(
    repo: String,
    repo_id: EntityId,
    policy: OriginLfsPathPolicy,
) -> OriginLfsPathPolicyView {
    OriginLfsPathPolicyView {
        repo,
        repo_id,
        revision: policy.revision,
        rules: policy.rules,
        default_class: LfsAssetClass::RepositoryLarge,
    }
}
