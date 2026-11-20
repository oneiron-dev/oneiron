//! Door to the recovery root's authority seed for the root's door tests
//! (pass 27 R4, `tests/owner_root_recovery.rs`): the bytes the recovery box
//! keeps, derived from a kit root's seed for a vault. Test support only.

use zeroize::Zeroizing;

use crate::authority::AuthorityVaultId;
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
