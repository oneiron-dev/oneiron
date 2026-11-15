//! Fixtures for the limits on a key only a passkey vouched for (lead ruling
//! WEBPASSKEY-BLIND-SIGNATURE = B): a revoke signed by a given owner key,
//! and a history of signed rows no door writes, which the fold judges.

use crate::authority::{AuthorityKey, AuthorityOp};
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

/// One row of [`append_signed_rows`]: its op, its primary signer and its
/// cosigners, each signing the row's authority transcript.
pub struct SignedRow {
    /// The row's op.
    pub op: AuthorityOp,
    /// Its primary signer.
    pub signer: AuthorityKey,
    /// Its cosigners, in order.
    pub cosigners: Vec<AuthorityKey>,
}

/// Signs and stores `rows` in one put, as the signed-row append door takes
/// a batch: the first at the vault's main-log heads, each later one on the
/// row before it, each signer at its next sequence. `sign` signs an
/// authority transcript as the key it names. True for each row the fold
/// counted.
///
/// # Errors
///
/// The store's refusal of the rows, or a frontier too wide for one entry.
pub fn append_signed_rows<S>(vault: &Vault, rows: Vec<SignedRow>, sign: S) -> Result<Vec<bool>>
where
    S: FnMut(&AuthorityKey, &[u8]) -> Vec<u8>,
{
    vault.append_signed_rows_for_test(
        rows.into_iter()
            .map(|row| (row.op, row.signer, row.cosigners))
            .collect(),
        sign,
    )
}
