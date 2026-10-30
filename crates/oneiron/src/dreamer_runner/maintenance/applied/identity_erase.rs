//! The erase scrub over the Dreamer's identity inverses (FIX 8707): each
//! settle's and each abstention's kept copy loses what came from the erased
//! id, reverted rows too. Its receipt, its revert and every other kind's
//! rows stay as they are.
use super::super::identity::{INVERSE_BY_SOURCE, inverse_ids, sync_inverse_sets};
use super::{APPLIED, MaintenanceInverse, MaintenanceTarget};
use crate::store::Store;
use crate::{EntityId, Result};

/// Takes the erased `id`'s bytes out of every identity inverse, in the
/// erase's own transaction; a row that held none is not written.
pub(in crate::dreamer_runner::maintenance) fn erase_identity_inverses_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    for (_, key) in INVERSE_BY_SOURCE.scan_keys(store, txn, id.as_bytes())? {
        let target = MaintenanceTarget::IdentityAsk(key);
        // A stale membership row names no inverse: an extra read, never a
        // scrub.
        let Some(mut row) = APPLIED.get(store, txn, &target)? else {
            continue;
        };
        let old = inverse_ids(&row.inverse);
        let changed = match &mut row.inverse {
            MaintenanceInverse::IdentitySettle(inverse) => inverse.erase_source(id),
            MaintenanceInverse::IdentityProvisional(inverse) => inverse.erase_source(id),
            _ => false,
        };
        if changed {
            APPLIED.put(store, txn, &target, &row)?;
            sync_inverse_sets(store, txn, &key, &old, &inverse_ids(&row.inverse))?;
        }
    }
    Ok(())
}
