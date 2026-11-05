//! Core half of `batch::phonetic_apply::checkpoint`: its store-layer items live in `oneiron_store::batch::phonetic_apply::checkpoint` and are
//! re-exported here; the items below stay in the engine.

#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

pub(crate) use oneiron_store::batch::phonetic_apply::checkpoint::*;

use heed::{RoTxn, RwTxn};
use super::PHONETIC_SOURCE;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator,
};

/// Every phonetic source row in `txn`, by entity.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    for row in rows::typed_rows(dbs, txn, PHONETIC_SOURCE, &mut out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    Ok(out)
}

fn owns(at: &RowLocator) -> bool {
    at.in_table(PHONETIC_SOURCE.decl())
}

/// The bundle framing of `rows`' phonetic source codes.
pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    rows::check_row(PHONETIC_SOURCE, at, value)
}

/// Puts `opened`'s phonetic source codes back exactly.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts(dbs, txn, &opened, check, rows::no_join)
}
