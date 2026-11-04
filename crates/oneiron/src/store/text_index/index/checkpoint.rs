//! The checkpoint getter of the bm25 index source (KS7-2): the canonical
//! caller-supplied text fields each document's postings are rebuilt from,
//! whole, under the document's entity tree. The postings themselves are an
//! index, rebuilt after a restore, and are not captured here. Nothing calls
//! this until KS7-5, and only once CHECKPOINT_PAYLOADS_ENABLED is on.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::{RoTxn, RwTxn};

use super::INDEX_SOURCE_TEXT;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator,
};

/// Every index-source text row in `txn`, by document.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    for row in rows::typed_rows(dbs, txn, INDEX_SOURCE_TEXT, &mut out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    Ok(out)
}

fn owns(at: &RowLocator) -> bool {
    at.in_table(INDEX_SOURCE_TEXT.decl())
}

/// The bundle framing of `rows`' index-source text.
pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    rows::check_row(INDEX_SOURCE_TEXT, at, value)
}

/// Puts `opened`'s index-source text back exactly.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts(dbs, txn, &opened, check, rows::no_join)
}
