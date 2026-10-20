//! The checkpoint rows of the staged index inputs (KS7-2): the caller's
//! fields, vector and token waiting for idle publication, whole, under their
//! entity's tree. The revision getter (`storage::checkpoint`) reads them.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::RoTxn;

use super::PENDING;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{self, Captured, OwnerRef, RowLocator};

pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>, out: &mut Captured) -> Result<()> {
    for row in rows::typed_rows(dbs, txn, PENDING, out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    Ok(())
}

pub(crate) fn owns(at: &RowLocator) -> bool {
    at.in_table(PENDING.decl())
}

pub(crate) fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    rows::check_row(PENDING, at, value)
}
