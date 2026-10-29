//! Destructive PPR-cache purge for hard erase.

use std::collections::HashSet;

use heed::RwTxn;

use super::{CACHE_DEP_KEY_LEN, SEED_HASH_LEN, delete_dep_rows_for_seed_hash};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::Result;
use crate::store::Store;

/// Deletes every payload that depends on an erased id or an incident neighbor,
/// together with every dependency key to that payload. Ordinary edge changes
/// keep their stale-only invalidation; this door is only for destructive erase.
pub(crate) fn purge_ppr_for_erase_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    neighbors: &[EntityId],
) -> Result<()> {
    let mut seed_hashes = HashSet::<[u8; SEED_HASH_LEN]>::new();
    let mut malformed_dep_keys = Vec::new();
    for entity in std::iter::once(id).chain(neighbors) {
        for entry in store
            .ppr_cache_deps
            .prefix_iter(&*wtxn, entity.as_bytes())?
        {
            let (key, _) = entry?;
            if key.len() != CACHE_DEP_KEY_LEN {
                malformed_dep_keys.push(key.to_vec());
                continue;
            }
            let mut seed_hash = [0_u8; SEED_HASH_LEN];
            seed_hash.copy_from_slice(&key[ENTITY_ID_LEN..CACHE_DEP_KEY_LEN]);
            seed_hashes.insert(seed_hash);
        }
    }

    for key in malformed_dep_keys {
        store.ppr_cache_deps.delete(wtxn, &key)?;
    }
    for seed_hash in seed_hashes {
        store.ppr_cache().delete(wtxn, &seed_hash)?;
        delete_dep_rows_for_seed_hash(store, wtxn, &seed_hash)?;
    }
    Ok(())
}
