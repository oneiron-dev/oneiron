//! The NOTE citation-pin index rows (KS7-2), each under its citing document
//! and holding while the document or claim it cites does. A source or claim
//! row leads with the cited id, then the citer; a citing row leads with the
//! citer. The quote and the pointer keys stay in the citer's compartment.

use heed::RoTxn;

use super::super::pin_index::{
    NOTE_PIN_CITING, NOTE_PIN_CLAIM, NOTE_PIN_REQUEST_CITING, NOTE_PIN_REQUEST_CLAIM,
    NOTE_PIN_REQUEST_SOURCE, NOTE_PIN_SOURCE,
};
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{self, Captured, OwnerRef, RowLocator};

pub(super) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>, out: &mut Captured) -> Result<()> {
    for row in rows::typed_rows(dbs, txn, NOTE_PIN_SOURCE, out)? {
        let owner = OwnerRef::entity(&row.key.1.0);
        out.depends(owner, &row.at, OwnerRef::entity(&row.key.0.0));
        out.depends(owner, &row.at, OwnerRef::entity(&row.value.claim));
        out.exact(owner, row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, NOTE_PIN_CLAIM, out)? {
        let owner = OwnerRef::entity(&row.key.1.0);
        out.depends(owner, &row.at, OwnerRef::entity(&row.key.0.0));
        out.exact(owner, row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, NOTE_PIN_CITING, out)? {
        let owner = OwnerRef::entity(&row.key.0.0);
        out.depends(owner, &row.at, OwnerRef::entity(&row.key.1.0));
        out.exact(owner, row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, NOTE_PIN_REQUEST_CITING, out)? {
        out.exact(OwnerRef::entity(&row.key.0.0), row.at, row.bytes);
    }
    for table in [NOTE_PIN_REQUEST_CLAIM, NOTE_PIN_REQUEST_SOURCE] {
        for row in rows::typed_rows(dbs, txn, table, out)? {
            let owner = OwnerRef::entity(&row.key.1.0);
            out.depends(owner, &row.at, OwnerRef::entity(&row.key.0.0));
            out.exact(owner, row.at, row.bytes);
        }
    }
    Ok(())
}

pub(super) fn owns(at: &RowLocator) -> bool {
    [
        NOTE_PIN_SOURCE.decl(),
        NOTE_PIN_CLAIM.decl(),
        NOTE_PIN_CITING.decl(),
        NOTE_PIN_REQUEST_CITING.decl(),
        NOTE_PIN_REQUEST_CLAIM.decl(),
        NOTE_PIN_REQUEST_SOURCE.decl(),
    ]
    .into_iter()
    .any(|decl| at.in_table(decl))
}

pub(super) fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(NOTE_PIN_SOURCE.decl()) {
        rows::check_row(NOTE_PIN_SOURCE, at, value)
    } else if at.in_table(NOTE_PIN_CLAIM.decl()) {
        rows::check_row(NOTE_PIN_CLAIM, at, value)
    } else if at.in_table(NOTE_PIN_CITING.decl()) {
        rows::check_row(NOTE_PIN_CITING, at, value)
    } else if at.in_table(NOTE_PIN_REQUEST_CITING.decl()) {
        rows::check_row(NOTE_PIN_REQUEST_CITING, at, value)
    } else if at.in_table(NOTE_PIN_REQUEST_CLAIM.decl()) {
        rows::check_row(NOTE_PIN_REQUEST_CLAIM, at, value)
    } else if at.in_table(NOTE_PIN_REQUEST_SOURCE.decl()) {
        rows::check_row(NOTE_PIN_REQUEST_SOURCE, at, value)
    } else {
        Err(rows::bad_part())
    }
}
