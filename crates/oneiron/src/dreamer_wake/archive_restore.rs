//! The owner's archive restore landing for `dreamer_wake` live tables: each envelope lands through
//! its owning check, or stays retained.

use crate::batch::export::ArchiveRetainedSideRow;
use crate::batch::export::OwnerArchiveRestorePermit;
use crate::batch::export::RetainedSideHeldBackReason;
use crate::batch::export::archive_side_install::ArchivedSideRowOutcome;
use crate::side_table;
use crate::{Result, Vault};

/// Lands archived `dreamer_wake` policy rows live, one outcome per input row in input order.
pub(crate) fn land_archived_dreamer_wake_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
) -> Result<Vec<ArchivedSideRowOutcome>> {
    let mut outcomes = Vec::with_capacity(rows.len());
    for row in rows {
        let outcome = match row.source_table.as_str() {
            name if name == side_table::DREAMER_PROJECTOR_POLICY.name => {
                super::projector::land_archived_dreamer_projector_policy_row_in_txn(
                    vault, txn, permit, row,
                )?
            }
            name if name == side_table::DREAMER_SIEVE_POLICY.name => {
                super::sieve::land_archived_dreamer_sieve_policy_row_in_txn(
                    vault, txn, permit, row,
                )?
            }
            name if name == side_table::DREAMER_WAKE_POLICY.name => {
                super::policy::land_archived_dreamer_wake_policy_row_in_txn(
                    vault, txn, permit, row,
                )?
            }
            name if name == side_table::DREAMER_WAKE_RECIPE_POLICY.name => {
                super::recipes::land_archived_dreamer_wake_recipe_policy_row_in_txn(
                    vault, txn, permit, row,
                )?
            }
            // The dispatcher never sends a foreign envelope here; without an
            // owning table the envelope has no decoding.
            _ => ArchivedSideRowOutcome::HeldBack(RetainedSideHeldBackReason::InvalidEncoding),
        };
        outcomes.push(outcome);
    }
    Ok(outcomes)
}
