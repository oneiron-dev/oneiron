//! A shared vault's member grants, for integration tests (primitive A, slice
//! 6.4f: the Steward arm of the run reader).

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    encode_federation_grant_body,
};
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Stands `member`'s live grant at `role` over shared vault `vault_id`, at
/// the scope the vault's policy resolves for the role, as a founding grant
/// is written. Only the Steward and Member roles are served here.
///
/// # Errors
///
/// Another role (`InvalidConfig`), and the vault's.
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
    let scope = {
        let txn = vault.store.env.read_txn()?;
        vault.grant_default_scope_in_txn(&txn, role, vault_id, member)?
    };
    let mut grant =
        FederationGrant::new(FederationGrantScope::vault(vault_id), member, role, preset);
    grant.authority_scope = scope;
    let id = EntityId::now();
    vault
        .batch()
        .put_replicated(
            &id,
            crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange { start: 1, end: 1 },
            1,
            None,
            &encode_federation_grant_body(&grant)?,
        )
        .commit()?;
    Ok(id)
}
