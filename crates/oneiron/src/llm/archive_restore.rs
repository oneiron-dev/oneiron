//! The owner's archive restore landing for `llm` live tables: the description policy installs
//! through the routing module's typed helper.

use crate::batch::export::ArchiveRetainedSideRow;
use crate::batch::export::OwnerArchiveRestorePermit;
use crate::batch::export::archive_side_install::ArchivedSideRowOutcome;
use crate::{Result, Vault};

/// Lands archived LLM_DESCRIPTION_POLICY rows live, one outcome per input row in input order.
pub(crate) fn land_archived_llm_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
) -> Result<Vec<ArchivedSideRowOutcome>> {
    let mut outcomes = Vec::with_capacity(rows.len());
    for row in rows {
        outcomes.push(
            super::routing::land_archived_llm_description_policy_row_in_txn(
                vault, txn, permit, row,
            )?,
        );
    }
    Ok(outcomes)
}
