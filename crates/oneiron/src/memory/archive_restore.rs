//! The owner's archive restore landing for `memory` live tables: the message-stream policy
//! installs through the stream module's typed helper.

use crate::batch::export::ArchiveRetainedSideRow;
use crate::batch::export::OwnerArchiveRestorePermit;
use crate::batch::export::archive_side_install::ArchivedSideRowOutcome;
use crate::{Result, Vault};

/// Lands the owner's archived `MESSAGE_STREAM_POLICY` envelopes in input order, one outcome
/// per row: an absent policy installs, an identical policy is unchanged, and a different
/// policy stays live. Open sessions keep their snapped settings.
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
        outcomes.push(
            crate::Vault::land_archived_message_stream_policy_row_in_txn(vault, txn, permit, row)?,
        );
    }
    Ok(outcomes)
}
