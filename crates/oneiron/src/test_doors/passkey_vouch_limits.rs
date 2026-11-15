//! Fixtures for the limits on a key only a passkey vouched for (lead ruling
//! WEBPASSKEY-BLIND-SIGNATURE = B): a revoke signed by a given owner key,
//! which the fold judges.

use crate::authority::AuthorityKey;
use crate::{Result, Vault};

/// Signs a `RevokeDevice` of `revoked` by `signer` alone (`sign` gets its
/// authority transcript) at the vault's main-log heads and stores it.
/// True when the fold counted it.
///
/// # Errors
///
/// The store's refusal of the entry, or a frontier too wide for one entry.
pub fn revoke_owner_key_signed_by<S>(
    vault: &Vault,
    signer: AuthorityKey,
    revoked: AuthorityKey,
    sign: S,
) -> Result<bool>
where
    S: FnOnce(&[u8]) -> Vec<u8>,
{
    vault.revoke_owner_key_signed_for_test(signer, revoked, sign)
}
