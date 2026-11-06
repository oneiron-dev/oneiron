//! The vault owner's reset of a person's step-up passkeys
//! (`vault.step_up.passkeys.reset`, FIX 17553).

use crate::Vault;
use crate::authority::{StepUpPasskeysReset, StepUpPasskeysResetRequest};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::memory::{MemoryError, MemoryResult};

/// Resets the passkeys of `input.person` as `owner`
/// ([`Vault::reset_step_up_passkeys_as_owner`]).
///
/// # Errors
/// `BAD_REQUEST` for a person that is no 32-hex id; the owner proof's
/// refusal; a storage fault.
pub fn reset_step_up_passkeys_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: StepUpPasskeysResetRequest,
) -> MemoryResult<StepUpPasskeysReset> {
    let person = EntityId::from_hex(&input.person)
        .map_err(|_| MemoryError::bad_request("person must be the 32-hex id of a person"))?;
    Ok(vault.reset_step_up_passkeys_as_owner(owner, person)?)
}
