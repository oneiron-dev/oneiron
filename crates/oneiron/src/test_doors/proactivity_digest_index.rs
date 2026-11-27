//! Doors for `tests/digest_erase_scrubs_stored_copies.rs` (PROACTIVITY-DIGEST-COPY-ERASURE).

use crate::dreamer_runner::maintenance::digest::{
    claim_digests_indexed_for_test, forget_claim_digest_index_for_test,
};

/// Clears the digest memberships and backfill marker without changing the digest rows.
///
/// # Errors
/// Returns a transaction, scan, or delete error.
pub fn forget_claim_digest_index(vault: &crate::Vault) -> crate::Result<()> {
    vault.with_write_txn_grouped(|txn| forget_claim_digest_index_for_test(&vault.store, txn))
}

/// Reads whether the digest membership backfill is marked complete.
///
/// # Errors
/// Returns a transaction or marker read error.
pub fn claim_digests_indexed(vault: &crate::Vault) -> crate::Result<bool> {
    let txn = vault.store.env.read_txn()?;
    claim_digests_indexed_for_test(&vault.store, &txn)
}
