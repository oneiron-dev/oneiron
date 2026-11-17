//! Doors for `tests/sync_live_file_custody_reuse.rs` (FIX 1370): the custody
//! records a stored file's mark names, value-free. The write door lifts each
//! key it finds in a file into its own custody record and records here where
//! the key sits and which record holds it (`store::file_key_masks`); the
//! test asserts the mark names the origin's record, not a duplicate the
//! import minted. Compiled only under `--cfg oneiron_test_support`
//! (`test_doors`). Hidden; never API.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::file_key_masks::masked_file_in_txn;

/// Each custody record the mark of the stored `bytes` names, in the stored
/// bytes then in each member, in mark order: no value, span or excerpt.
/// Empty where the write door kept no keys in the file.
///
/// # Errors
///
/// The store's.
#[doc(hidden)]
pub fn file_mark_custody(vault: &Vault, bytes: &[u8]) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let hash = blake3::hash(bytes);
    let Some(mark) = masked_file_in_txn(&vault.store, &txn, hash.as_bytes())? else {
        return Ok(Vec::new());
    };
    let mut custody: Vec<EntityId> = mark.keys.iter().map(|key| key.custody).collect();
    for member in &mark.members {
        custody.extend(member.keys.iter().map(|key| key.custody));
    }
    Ok(custody)
}
