//! A managed person's proof, for integration tests (L7-17 PR 2): the proof
//! a managed host's member door builds for a supervisor-signed person
//! action naming `person` (`oneiron-server` `managed_person_proof`), with
//! the action's `mfa_verified` claim when the supervisor signed it.

use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::GateDecisionId;
use crate::vault::Vault;

/// The slipless proof of `person` a managed member door builds; on this
/// tree a supervisor's `mfa_verified` claim has no engine form, so the
/// proof carries nothing for it.
///
/// # Errors
///
/// The vault's refusal to authenticate `person`.
pub fn managed_person_proof(
    vault: &Vault,
    person: EntityId,
    mfa_verified: bool,
) -> Result<AuthenticatedOwner> {
    let proof = vault.authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())?;
    let _ = mfa_verified;
    Ok(proof)
}
