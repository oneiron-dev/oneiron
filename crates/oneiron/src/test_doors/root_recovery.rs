//! Door to the recovery root's authority seed for the root's door tests
//! (pass 27 R4, `tests/owner_root_recovery.rs`): the bytes the recovery box
//! keeps, derived from a kit root's seed for a vault. Test support only.

use zeroize::Zeroizing;

use crate::Vault;
use crate::authority::{
    ActSurface, AuthorityKey, AuthorityVaultId, RootMaterial, RootRecovery, RootSuccessor,
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
