//! The owner's archive restore over the web connector tables: each envelope lands through its owning
//! check, or stays retained.

use super::setting::land_archived_web_connector_setting_row_in_txn;
use crate::Vault;
use crate::batch::export::archive_side_install::ArchivedSideRowOutcome;
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::error::Result;
use crate::side_table;

/// Lands the owner's archived web connector envelopes in input order.
pub(crate) fn land_archived_web_connector_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
) -> Result<Vec<ArchivedSideRowOutcome>> {
    let mut outcomes = Vec::with_capacity(rows.len());
    for row in rows {
        let outcome = match row.source_table.as_str() {
            name if name == side_table::WEB_CONNECTOR_SETTING.name => {
                land_archived_web_connector_setting_row_in_txn(vault, txn, permit, row)?
            }
            // The dispatcher never sends a foreign envelope here; without an
            // owning table the envelope has no decoding.
            _ => ArchivedSideRowOutcome::HeldBack(RetainedSideHeldBackReason::InvalidEncoding),
        };
        outcomes.push(outcome);
    }
    Ok(outcomes)
}
