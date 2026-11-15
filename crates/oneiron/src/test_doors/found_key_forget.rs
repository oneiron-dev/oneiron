//! Doors for `tests/found_key_ruled_screen.rs` (L6-03-RULED-SCREEN-LOCAL):
//! this install put, for one record, in the state of the owner's other
//! machine, which holds none of the record's found keys until a ruling's
//! carried revoke reaches it.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Moves `record`'s found keys, and whatever follows them, to a fresh
/// scratch id: this install then holds no found key of `record`, and no
/// value the owner kept there, as the owner's other machine holds none
/// before its owner work drain folds the ruling's revoke.
///
/// # Errors
/// The store's.
pub fn forget_found_keys_of(vault: &Vault, record: EntityId) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    crate::secret_custody::move_side_row_custody_in_txn(
        &vault.store,
        &mut wtxn,
        &record,
        &EntityId::now(),
    )?;
    wtxn.commit()?;
    Ok(())
}
