//! The device's confirmed shared-vault leave receipts, also read before
//! open-time bootstrap.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

#[doc(hidden)]
pub use oneiron_records::store::shared_leave_receipt::{SharedLeaveKind, SharedLeaveReceipt};

/// This device's leave records, keyed by the notice's receipt id.
pub(crate) const LEAVE_RECEIPTS: SideTable<String, SharedLeaveReceipt, Named> =
    SideTable::new(&side_table::SYNC_SHARED_LEAVE_RECEIPT);

/// Whether this dedicated shared environment holds a confirmed leave receipt.
///
/// # Errors
///
/// Storage and receipt-decoding errors.
pub(crate) fn has_left(store: &Store) -> Result<bool> {
    let txn = store.env.read_txn()?;
    Ok(LEAVE_RECEIPTS
        .iter_from(store, &txn, &[])?
        .next()
        .transpose()?
        .is_some())
}
