//! Doors for `tests/found_key_sealed_file_carry.rs` (Engine RULING
//! PLAN-SEALED-FILE-RULING-CARRY): this install put in the state of the
//! owner's other install, where a file's bytes arrived by sync with no
//! mark, since no write door read them there.

use crate::Vault;
use crate::error::Result;

/// Drops the mark of `bytes`, a file this vault stores: the vault then
/// holds no mark of them, as an install that got them by sync holds none.
///
/// # Errors
/// The store's.
pub fn forget_file_mark_of(vault: &Vault, bytes: &[u8]) -> Result<()> {
    let hash = *blake3::hash(bytes).as_bytes();
    let mut wtxn = vault.store.env.write_txn()?;
    crate::store::file_key_masks::forget_masked_file_in_txn(&vault.store, &mut wtxn, &hash)?;
    wtxn.commit()?;
    Ok(())
}
