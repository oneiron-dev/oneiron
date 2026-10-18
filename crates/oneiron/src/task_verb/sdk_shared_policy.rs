//! The shared-act policy rows a host door answers (DOOR-129):
//! `vault.shared.policy.get` reads every row a live Owner may inspect. Each
//! fn passes the engine exactly what it asks for.
use super::sdk_shared::SharedVaultRequest;
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::federation::SharedActPoliciesView;
use crate::memory::MemoryResult;

/// `vault.shared.policy.get`: every shared-act policy row of the vault.
pub fn read_shared_act_policies(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: SharedVaultRequest,
) -> MemoryResult<SharedActPoliciesView> {
    Ok(vault.shared_act_policies(owner, input.vault_id)?)
}
