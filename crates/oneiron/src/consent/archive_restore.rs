//! Owner restore of archived consent rows (SIDE-4b G1/G2 plus the group dispatcher).
//!
//! Each archived `CONSENT_STANDING_GRANT` row lands only when its key still names its
//! recomputed grant digest, its live-row writer checks hold, and its stamp actor is a live
//! `PERSON`; revoked rows install as inert history. Each archived
//! `CONSENT_APPROVE_ONCE_MARKER` row lands when its state byte is available or spent.
//! Widen rows land through the worker beside the private widen table, which this dispatcher
//! calls in input order. No landing mints a grant, writes a receipt, or notifies; the shared
//! archive installer queues the consent-answer refresh after commit.

use super::codec::GRANTS;
use super::support::{
    APPROVE_ONCE_MARKERS, CONSENT_APPROVE_ONCE_AVAILABLE, CONSENT_APPROVE_ONCE_SPENT,
};
use crate::Vault;
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::error::Result;
use crate::side_table;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Lands archived consent envelopes in input order, one outcome per row.
pub(crate) fn land_archived_consent_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
) -> Result<Vec<ArchivedSideRowOutcome>> {
    let mut outcomes = Vec::with_capacity(rows.len());
    for row in rows {
        let outcome = match row.source_table.as_str() {
            name if name == side_table::CONSENT_STANDING_GRANT.name => {
                land_archived_consent_grant_row_in_txn(vault, txn, permit, row)?
            }
            name if name == side_table::CONSENT_APPROVE_ONCE_MARKER.name => {
                land_archived_approve_once_row_in_txn(vault, txn, permit, row)?
            }
            name if name == side_table::CONSENT_WIDEN_PROPOSAL.name => {
                crate::consent::widen::archive_restore::land_archived_widen_row_in_txn(
                    vault, txn, permit, row,
                )?
            }
            // The dispatcher never sends a foreign envelope here; without an owning table the
            // envelope has no decoding.
            _ => ArchivedSideRowOutcome::HeldBack(RetainedSideHeldBackReason::InvalidEncoding),
        };
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

/// Lands one archived standing-grant row after its digest, writer, and stamp checks.
fn land_archived_consent_grant_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    row: &ArchiveRetainedSideRow,
) -> Result<ArchivedSideRowOutcome> {
    use RetainedSideHeldBackReason::{
        InvalidEncoding, InvalidValue, MissingLiveEntity, WrongEntityKind,
    };
    let (key, value) = match decode_archived_row(&GRANTS, row) {
        Err(reason) => return Ok(ArchivedSideRowOutcome::HeldBack(reason)),
        Ok(decoded) => decoded,
    };
    if crate::consent::consent_grant_row_grant_ref(&value) != key {
        return Ok(ArchivedSideRowOutcome::HeldBack(InvalidEncoding));
    }
    // Writer field checks for live rows only; revoked history installs below after its stamp
    // check. The codec already validated the bound shape, status, stamp encoding, and bypass
    // encoding. Every Active catastrophe-bound row holds back, including a valid bypass row,
    // which is catastrophe-bound by construction; every Active bypass row holds back, which
    // also rejects writer-invalid bypass shapes (non-catastrophe or non-action).
    if value.is_active()
        && (crate::consent::bound_catastrophe_class(value.grant.bound()).is_some()
            || value.bypass.is_some())
    {
        return Ok(ArchivedSideRowOutcome::HeldBack(InvalidValue));
    }
    match live_entity_row_in_txn(&vault.store, &*txn, &value.owner_stamp.actor)? {
        LiveEntityRow::Live { entity_type, .. }
            if entity_type == crate::registry::ENTITY_TYPE_PERSON => {}
        LiveEntityRow::Live { .. } => {
            return Ok(ArchivedSideRowOutcome::HeldBack(WrongEntityKind));
        }
        LiveEntityRow::Absent | LiveEntityRow::DeletedShell => {
            return Ok(ArchivedSideRowOutcome::HeldBack(MissingLiveEntity));
        }
    }
    // Writer liveness reuse: a live PERSON shell whose identity lifecycle is not Active
    // (merged or split) holds back like an absent actor.
    if !crate::consent::doors::person_is_live_in_txn(vault, &*txn, &value.owner_stamp.actor)? {
        return Ok(ArchivedSideRowOutcome::HeldBack(MissingLiveEntity));
    }
    let outcome = install_archived_row(&GRANTS, vault, txn, permit, &key, row)?;
    if matches!(outcome, ArchivedSideRowOutcome::Installed) {
        // Derived outbound-grant index keys only; the row write above is the authority.
        crate::outbound_grant::index_standing_outbound_grant_row_in_txn(
            &vault.store,
            txn,
            &key,
            &value,
        )?;
    }
    Ok(outcome)
}

/// Lands one archived approve-once marker whose state byte the writer could have stored.
fn land_archived_approve_once_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    row: &ArchiveRetainedSideRow,
) -> Result<ArchivedSideRowOutcome> {
    use RetainedSideHeldBackReason::InvalidEncoding;
    let (key, value) = match decode_archived_row(&APPROVE_ONCE_MARKERS, row) {
        Err(reason) => return Ok(ArchivedSideRowOutcome::HeldBack(reason)),
        Ok(decoded) => decoded,
    };
    if value.state != CONSENT_APPROVE_ONCE_AVAILABLE && value.state != CONSENT_APPROVE_ONCE_SPENT {
        return Ok(ArchivedSideRowOutcome::HeldBack(InvalidEncoding));
    }
    install_archived_row(&APPROVE_ONCE_MARKERS, vault, txn, permit, &key, row)
}
