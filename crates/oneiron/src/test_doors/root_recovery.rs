//! Door to the recovery root's authority seed for the root's door tests
//! (pass 27 R4, `tests/owner_root_recovery.rs`): the bytes the recovery box
//! keeps, derived from a kit root's seed for a vault. Test support only.

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::Vault;
use crate::authority::{
    ActSurface, AuthorityKey, AuthorityVaultId, RootMaterial, RootRecovery, RootSuccessor,
    invalid_authority,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::world_keys::{RecoveryAuthoritySigner, RecoveryRootSeed};

/// The authority key's own seed that `seed` derives for `vault_id` at
/// `generation`, as the recovery box would hold it. Generation 0 is today's
/// bytes exactly.
#[must_use]
pub fn released_authority_seed(
    seed: &RecoveryRootSeed,
    vault_id: &AuthorityVaultId,
    generation: u32,
) -> Zeroizing<[u8; 32]> {
    RecoveryAuthoritySigner::authority_seed(seed, vault_id, generation)
}

/// [`Vault::recover_owner_root`] with an explicit wait (OPUS-WAYBACK): the
/// seam so tests cover zero and nonzero waits. A box recovery
/// (`RootMaterial::Released`) with a nonzero wait holds instead of
/// vouching; a zero wait vouches as today. The kit arm never waits.
pub fn recover_owner_root_waiting(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    material: RootMaterial,
    successor: RootSuccessor,
    lost: &[AuthorityKey],
    wait: std::time::Duration,
) -> Result<RootRecovery> {
    vault.recover_owner_root_with_wait(owner, surface, material, successor, lost, wait)
}

/// Stages the state after a crash between the keystore put and the hold
/// commit: `seed` in this install's hold slot for `successor`, with its
/// pending record, and no hold naming it.
pub fn stage_orphan_recovery_hold_seed(
    vault: &Vault,
    successor: [u8; 32],
    seed: &[u8; 32],
) -> Result<()> {
    let machine = vault.prepare_install_signing()?;
    let vault_id = {
        let txn = vault.store.env.read_txn()?;
        vault
            .authority_view_readonly_in_txn(&txn)?
            .vault_id
            .ok_or_else(invalid_authority)?
    };
    let mut pending = vault.store.env.write_txn()?;
    vault.put_recovery_hold_slot_pending_in_txn(&mut pending, &successor)?;
    pending.commit()?;
    let slot = vault.recovery_hold_slot(&vault_id, machine, &successor);
    let seed = Zeroizing::new(*seed);
    let expected = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    vault.put_recovery_hold_seed(&slot, &seed, &expected)?;
    Ok(())
}

/// Whether this install's hold slot for `successor` keeps a seed.
pub fn recovery_hold_seed_present(vault: &Vault, successor: [u8; 32]) -> Result<bool> {
    let machine = vault.prepare_install_signing()?;
    let vault_id = {
        let txn = vault.store.env.read_txn()?;
        vault
            .authority_view_readonly_in_txn(&txn)?
            .vault_id
            .ok_or_else(invalid_authority)?
    };
    let slot = vault.recovery_hold_slot(&vault_id, machine, &successor);
    Ok(vault.read_recovery_hold_seed(&slot)?.is_some())
}

/// Every successor whose hold seed slot this install may hold, in key
/// order: the pending records.
pub fn recovery_hold_slots_pending(vault: &Vault) -> Result<Vec<[u8; 32]>> {
    let txn = vault.store.env.read_txn()?;
    vault.recovery_hold_slots_pending_in_txn(&txn)
}
