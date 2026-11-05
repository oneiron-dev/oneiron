//! Checkpoint payload projection for the workflow transcript pointer and
//! settled meter. The actor owns the whole row; known sources and the room
//! are dependencies, independently of whether the source set is complete.

use heed::{RoTxn, RwTxn};

use super::{TABLE, key};
use crate::Result;
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator, Unresolved,
};

pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    for row in rows::typed_rows(dbs, txn, TABLE, &mut out)? {
        if key(row.value.attempt)? != row.key {
            out.unclassified(row.at, None, Unresolved::NoOwner);
            continue;
        }
        let Some(content) = row.value.binding() else {
            out.structure(row.at, row.bytes, Vec::new());
            continue;
        };
        let owner = OwnerRef::entity(&content.actor);
        for source in content.known_sources.iter().copied().chain(content.room) {
            out.depends(owner, &row.at, OwnerRef::entity(&source));
        }
        out.exact(owner, row.at, row.bytes);
    }
    Ok(out)
}

fn owns(at: &RowLocator) -> bool {
    at.in_table(TABLE.decl())
}

pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts(
        dbs,
        txn,
        &opened,
        |at, value| rows::check_row(TABLE, at, value),
        rows::no_join,
    )
}
