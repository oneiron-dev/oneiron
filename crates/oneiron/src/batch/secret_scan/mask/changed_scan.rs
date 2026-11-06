//! Core half of `batch::secret_scan::mask::changed_scan`: its store-layer items live in `oneiron_store::batch::secret_scan::mask::changed_scan` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::secret_scan::mask::changed_scan::*;

use super::super::scan_batch_ops;
use crate::batch::BatchOp;
use crate::error::Result;
use crate::store::Store;
use heed::RoTxn;

/// The door's scan of `planned`, the plan's copy of `read`, which the
/// door's first scan read clean: each op the plan changed, in op order.
pub(super) fn scan_changed_ops(
    store: &Store,
    txn: &RoTxn<'_>,
    planned: &[BatchOp],
    read: &[BatchOp],
) -> Result<()> {
    for (op, before) in planned.iter().zip(read) {
        if !scan_reads_same(op, before) {
            scan_batch_ops(store, txn, std::slice::from_ref(op))?;
        }
    }
    Ok(())
}
