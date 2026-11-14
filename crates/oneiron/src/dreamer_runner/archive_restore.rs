//! The owner's archive restore landing for `dreamer_runner` live tables: the action-mode
//! policy installs through the maintenance module's typed helper.

use crate::batch::export::ArchiveRetainedSideRow;
use crate::batch::export::OwnerArchiveRestorePermit;
use crate::batch::export::archive_side_install::ArchivedSideRowOutcome;
use crate::{Result, Vault};

/// Lands the owner's archived `DREAMER_ACTION_MODE_POLICY` envelopes in input order, one
/// outcome per row: an absent policy installs, an identical policy is unchanged, and a
/// different policy stays live. Nothing is measured or applied.
///
/// # Errors
/// Storage faults; validation stays in the returned outcomes.
pub(crate) fn land_archived_dreamer_runner_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
) -> Result<Vec<ArchivedSideRowOutcome>> {
    let mut outcomes = Vec::with_capacity(rows.len());
    for row in rows {
        outcomes.push(
            super::maintenance::action_mode::land_archived_dreamer_action_mode_policy_row_in_txn(
                vault, txn, permit, row,
            )?,
        );
    }
    Ok(outcomes)
}
