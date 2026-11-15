//! Fixtures for the limits on a key only a passkey vouched for (lead ruling
//! WEBPASSKEY-BLIND-SIGNATURE = B): a revoke signed by a given owner key,
//! and a history of signed rows no door writes, at the main-log heads or on
//! a sibling branch, which the fold judges.

use crate::authority::{
    ActAuthority, AuthorityEntryHash, AuthorityKey, AuthorityOp, OwnerKeyEnrollment,
};
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
    append_signed_rows_at(vault, None, rows, sign)
}

/// As [`append_signed_rows`], the first row on `parents` in place of the
/// vault's main-log heads: a sibling branch of every row stored since those
/// heads (Astra stack review finding 1).
///
/// # Errors
///
/// The store's refusal of the rows.
pub fn append_signed_rows_on<S>(
    vault: &Vault,
    parents: Vec<AuthorityEntryHash>,
    rows: Vec<SignedRow>,
    sign: S,
) -> Result<Vec<bool>>
where
    S: FnMut(&AuthorityKey, &[u8]) -> Vec<u8>,
{
    append_signed_rows_at(vault, Some(parents), rows, sign)
}

/// The owner key enrollment of `input`'s key on `parents`, a sibling branch
/// of every row stored since: signed by `predecessor` (`sign` gets its
/// authority transcript), cosigned by this install as its carrier, with no
/// roster check of the door's own. True when the fold counted it (Astra
/// delta review finding 2).
///
/// # Errors
///
/// An agent's act, an install that cannot carry it, an owner proof that no
/// longer holds, or the store's refusal of the row.
pub fn enrol_owner_key_on<S>(
    vault: &Vault,
    authority: &ActAuthority,
    input: OwnerKeyEnrollment,
    parents: Vec<AuthorityEntryHash>,
    predecessor: AuthorityKey,
    sign: S,
) -> Result<bool>
where
    S: FnOnce(&[u8]) -> Vec<u8>,
{
    vault.enrol_owner_key_on_parents_for_test(authority, input, parents, predecessor, sign)
}

/// The vault's main-log heads now, the parents a row appended now names.
///
/// # Errors
///
/// The store's read error.
pub fn main_log_heads(vault: &Vault) -> Result<Vec<AuthorityEntryHash>> {
    vault.main_log_heads_for_test()
}

fn append_signed_rows_at<S>(
    vault: &Vault,
    parents: Option<Vec<AuthorityEntryHash>>,
    rows: Vec<SignedRow>,
    sign: S,
) -> Result<Vec<bool>>
where
    S: FnMut(&AuthorityKey, &[u8]) -> Vec<u8>,
{
    vault.append_signed_rows_for_test(
        rows.into_iter()
            .map(|row| (row.op, row.signer, row.cosigners))
            .collect(),
        parents,
        sign,
    )
}
