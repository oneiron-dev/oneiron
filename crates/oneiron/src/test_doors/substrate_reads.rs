//! A Steward grant narrowed to one project, for the integration test of the
//! substrate reads behind a grant (untangle 6.6c; review of #6996).

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

/// Stands a Steward grant on the vault's root for `holder` with `verbs`,
/// its audience narrowed to the one project `project`, as a holder override
/// row leaves a member's grant.
///
/// # Errors
///
/// The vault's.
pub fn stand_project_steward_grant(
    vault: &Vault,
    holder: EntityId,
    verbs: &[&str],
    project: EntityId,
) -> Result<EntityId> {
    vault.stand_project_steward_grant_for_test(holder, verbs, project)
}
