//! The owner's archive restore landing for `esign` live tables: audit rows install through the
//! ledger module's typed helper, which preflights each document's merged chain before any put.

use crate::batch::export::ArchiveRetainedSideRow;
use crate::batch::export::OwnerArchiveRestorePermit;
use crate::batch::export::archive_side_install::ArchivedSideRowOutcome;
use crate::{Result, Vault};

/// Lands the owner's archived `ESIGN_AUDIT` envelopes in input order, one outcome per row: an
/// absent row installs once its document's merged chain validates, an identical row is
/// unchanged, and a different row stays live. No claim is minted and no live document is needed.
///
/// # Errors
/// Storage faults; validation stays in the returned outcomes.
pub(crate) fn land_archived_esign_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
) -> Result<Vec<ArchivedSideRowOutcome>> {
    super::ledger::land_archived_esign_rows_in_txn(vault, txn, permit, rows)
}
