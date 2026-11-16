//! A shared vault's member grants, for integration tests (primitive A, slice
//! 6.4f: the Steward arm of the run reader).

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
};
use crate::vault::Vault;

/// Stands `member`'s live grant at `role` over shared vault `vault_id`, at
/// the scope the vault's policy resolves for the role, as a founding grant
/// is written: the vault's creator gives it by its counted act (pass 28 R2),
/// so the fold stands behind it (R3). Only the Steward and Member roles are
/// served here.
///
/// # Errors
///
/// Another role (`InvalidConfig`), a vault with no shared creation record, an
/// install that cannot carry the act, and the vault's.
pub fn stand_member_grant(
    vault: &Vault,
    member: EntityId,
    vault_id: u64,
    role: FederationGrantRole,
) -> Result<EntityId> {
    let preset = match role {
        FederationGrantRole::Steward => FederationGrantPreset::Steward,
        FederationGrantRole::Member => FederationGrantPreset::Member,
        _ => {
            return Err(Error::InvalidConfig(format!(
                "this door stands Steward and Member grants, not {role:?}"
            )));
        }
    };
    let (scope, creator) = {
        let txn = vault.store.env.read_txn()?;
        let creation = vault
            .shared_vault_creation_in_txn(&txn)?
            .ok_or_else(|| Error::InvalidConfig("no shared vault here".to_owned()))?;
        (
            vault.grant_default_scope_in_txn(&txn, role, vault_id, member)?,
            EntityId::from_hex(&creation.owner_ref)?,
        )
    };
    let mut grant =
        FederationGrant::new(FederationGrantScope::vault(vault_id), member, role, preset);
    grant.authority_scope = scope;
    let id = EntityId::now();
    super::grant_act::give_member_grant_as_writer(vault, id, &grant, creator)?;
    Ok(id)
}
