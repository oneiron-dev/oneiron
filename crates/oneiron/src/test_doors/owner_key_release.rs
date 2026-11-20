//! This install's owner keys, for the integration tests of the owner-proof
//! rule (rows CARRIER-OWNER-PROOF and OLD-PARENTS-OWNER-BINDING-REVOKE): an
//! install that holds no owner key, and the owner's binding with an owner
//! key's proof on a hosted vault. The root signers a handle holds and the
//! host root's signing are crate-private.

use crate::Vault;
use crate::authority::HostSlipIssuer;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Drops every root signer this handle holds. The roster keeps every key it
/// names, so the vault still holds an owner key while this install holds
/// none: the state of an install beside the owner's device.
pub fn release_owner_keys(vault: &Vault) {
    vault.release_checkpoint_root_signers();
}

/// Binds `person` as the human owner under the host root `issuer`, as the
/// owner binds from a device of their own: under `owner`'s act this install
/// enrols its owner signing key, and that key cosigns the host root's bind.
/// A hosted fold counts a `human` bind only with an owner key's proof (owner
/// ruling 2026-10-18: the operator root acts as nobody inside a customer's
/// vault), and a door that needs the owner's binding there, such as
/// [`Vault::recover_cloud_account`], reads this one.
///
/// # Errors
///
/// The enrolment's refusals, or the authority log's.
pub fn bind_owner_with_owner_key(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    issuer: &HostSlipIssuer,
    person: EntityId,
) -> Result<()> {
    vault.bind_host_owner_with_owner_key_for_test(owner, issuer, person)
}
