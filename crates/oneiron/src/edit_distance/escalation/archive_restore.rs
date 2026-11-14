//! Owner restore of archived escalation standing-policy rows (SIDE-4c).
//!
//! A row lands only when its key governs what it carries: the scope digest,
//! the trigger and a coherent ruling. Cited receipts dangle safely (never
//! dereferenced) and the escalation ledger does not travel.

use super::storage::{STANDING_POLICY, STANDING_POLICY_ROW_LABEL, ruling_from_parts, scope_key};
use super::types::EscalationTrigger;
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::error::Result;

/// Lands archived escalation standing-policy rows in input order, one outcome per row.
///
/// No liveness check: the row names no entity. Scope shape, row and holder
/// refs, the band ceiling and cited receipts travel as-is.
///
/// # Errors
/// Storage faults; validation stays in the returned outcomes.
pub(crate) fn land_archived_escalation_policy_rows_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
) -> Result<Vec<ArchivedSideRowOutcome>> {
    use RetainedSideHeldBackReason::InvalidValue;

    let mut outcomes = Vec::with_capacity(rows.len());
    for row in rows {
        let outcome = match decode_archived_row(&STANDING_POLICY, row) {
            Err(reason) => ArchivedSideRowOutcome::HeldBack(reason),
            Ok((key, value)) => {
                let coherent = key.scope_digest == scope_key(&value.scope)
                    && EscalationTrigger::from_token(&value.trigger) == Some(key.trigger)
                    && ruling_from_parts(
                        &value.ruling,
                        value.delta.as_deref(),
                        STANDING_POLICY_ROW_LABEL,
                    )
                    .is_ok();
                if coherent {
                    install_archived_row(&STANDING_POLICY, vault, txn, permit, &key, row)?
                } else {
                    ArchivedSideRowOutcome::HeldBack(InvalidValue)
                }
            }
        };
        outcomes.push(outcome);
    }
    Ok(outcomes)
}
