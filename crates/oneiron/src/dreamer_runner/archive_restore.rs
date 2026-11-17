//! The owner's archive restore landing for `dreamer_runner` live tables: the action-mode
//! policy and free-time receipts install through their owning modules' typed helpers.

use crate::batch::export::ArchiveRetainedSideRow;
use crate::batch::export::OwnerArchiveRestorePermit;
use crate::batch::export::RetainedSideHeldBackReason;
use crate::batch::export::archive_side_install::ArchivedSideRowOutcome;
use crate::side_table;
use crate::{Result, Vault};

/// Lands the owner's archived `dreamer_runner` envelopes in input order, one outcome per row:
/// an absent row installs, an identical row is unchanged, and a different row stays live.
/// Receipts never reopen a cycle or settle spend.
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
        let outcome = match row.source_table.as_str() {
            name if name == side_table::DREAMER_ACTION_MODE_POLICY.name => {
                super::maintenance::action_mode::land_archived_dreamer_action_mode_policy_row_in_txn(
                    vault, txn, permit, row,
                )?
            }
            name if name == side_table::DREAMER_FREE_TIME_RECEIPT.name => {
                Vault::land_archived_dreamer_free_time_receipt_row_in_txn(vault, txn, permit, row)?
            }
            // The dispatcher never sends a foreign envelope here; without an
            // owning table the envelope has no decoding.
            _ => ArchivedSideRowOutcome::HeldBack(RetainedSideHeldBackReason::InvalidEncoding),
        };
        outcomes.push(outcome);
    }
    Ok(outcomes)
}
