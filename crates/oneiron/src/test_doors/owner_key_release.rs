//! An install that holds no owner key, for the integration tests of the
//! owner-proof rule (row CARRIER-OWNER-PROOF): the root signers a handle
//! holds are crate-private.

use crate::Vault;

/// Drops every root signer this handle holds. The roster keeps every key it
/// names, so the vault still holds an owner key while this install holds
/// none: the state of an install beside the owner's device.
pub fn release_owner_keys(vault: &Vault) {
    vault.release_checkpoint_root_signers();
}
