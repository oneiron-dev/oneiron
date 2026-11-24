//! TEST-ONLY: the store's committed write transactions, so a test can pin
//! that a read door writes nothing at all (design pass 32, T24).

use crate::Vault;

/// The id of the last write transaction the vault's store committed (LMDB's
/// `last_txn_id`). Every commit raises it; a read that writes nothing leaves
/// it as it was.
#[must_use]
pub fn last_committed_write(vault: &Vault) -> usize {
    vault.store.env.info().last_txn_id
}
