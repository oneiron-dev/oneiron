//! The owner's archive restore landing for `dreamer_wake` live tables: the projector policy
//! installs through the projector's typed helper.

use crate::batch::export::ArchiveRetainedSideRow;
use crate::batch::export::OwnerArchiveRestorePermit;
use crate::batch::export::archive_side_install::ArchivedSideRowOutcome;
use crate::{Result, Vault};

/// Lands archived DREAMER_PROJECTOR_POLICY rows live, one outcome per input row in input order.
pub(crate) fn land_archived_dreamer_wake_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
) -> Result<Vec<ArchivedSideRowOutcome>> {
    let mut outcomes = Vec::with_capacity(rows.len());
    for row in rows {
        outcomes.push(
            super::projector::land_archived_dreamer_projector_policy_row_in_txn(
                vault, txn, permit, row,
            )?,
        );
    }
    Ok(outcomes)
}
