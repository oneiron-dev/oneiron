//! The owner's archive restore landing for `memory` live tables: the message-stream policy
//! installs through the stream module's typed helper and export audit rows through their own.

use crate::batch::export::ArchiveRetainedSideRow;
use crate::batch::export::OwnerArchiveRestorePermit;
use crate::batch::export::RetainedSideHeldBackReason;
use crate::batch::export::archive_side_install::ArchivedSideRowOutcome;
use crate::side_table;
use crate::{Result, Vault};

/// Lands the owner's archived `MESSAGE_STREAM_POLICY` and `EXPORT_RECEIPT` envelopes in input
/// order, one outcome per row: an absent row installs, an identical row is unchanged, and a
/// different row stays live. Open sessions keep their snapped settings; export copies, acts,
/// holder requests and thread notices are never replayed.
///
/// # Errors
/// Storage faults; validation stays in the returned outcomes.
pub(crate) fn land_archived_memory_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
) -> Result<Vec<ArchivedSideRowOutcome>> {
    let mut outcomes = Vec::with_capacity(rows.len());
    for row in rows {
        let outcome = match row.source_table.as_str() {
            name if name == side_table::MESSAGE_STREAM_POLICY.name => {
                crate::Vault::land_archived_message_stream_policy_row_in_txn(
                    vault, txn, permit, row,
                )?
            }
            name if name == side_table::EXPORT_RECEIPT.name => {
                super::export_audit::land_archived_export_receipt_row_in_txn(
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
