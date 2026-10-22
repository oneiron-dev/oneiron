//! The erase scrub over the Dreamer's identity inverses (FIX 8707): each
//! settle's and each abstention's kept copy loses what came from the erased
//! id, reverted rows too. Its receipt, its revert and every other kind's
//! rows stay as they are.
use super::{APPLIED, MaintenanceInverse};
use crate::store::Store;
use crate::{EntityId, Result};

/// Takes the erased `id`'s bytes out of every identity inverse, in the
/// erase's own transaction; a row that held none is not written.
pub(in crate::dreamer_runner::maintenance) fn erase_identity_inverses_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    for (target, mut row) in APPLIED.scan(store, txn)? {
        let changed = match &mut row.inverse {
            MaintenanceInverse::IdentitySettle(inverse) => inverse.erase_source(id),
            MaintenanceInverse::IdentityProvisional(inverse) => inverse.erase_source(id),
            _ => false,
        };
        if changed {
            APPLIED.put(store, txn, &target, &row)?;
        }
    }
    Ok(())
}
