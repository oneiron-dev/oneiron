//! Media vectors and device provenance, under each source document's entity tree.
//! Refusal rows stay outside this getter so bare and kept-current restores retain
//! their existing LIVE-row behavior.

use heed::{RoTxn, RwTxn};

use super::MEDIA_VECTOR;
use crate::embed::EmbeddingProvenance;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator,
};

const MEDIA_DEVICE: SideTable<([u8; 16], EntityId), EmbeddingProvenance, Named> =
    SideTable::new(&side_table::EMBEDDING_MEDIA_DEVICE);

pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    for row in rows::typed_rows(dbs, txn, MEDIA_VECTOR, &mut out)? {
        out.exact(OwnerRef::entity(&row.key.1), row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, MEDIA_DEVICE, &mut out)? {
        out.exact(OwnerRef::entity(&row.key.1), row.at, row.bytes);
    }
    Ok(out)
}

fn owns(at: &RowLocator) -> bool {
    at.in_table(MEDIA_VECTOR.decl()) || at.in_table(MEDIA_DEVICE.decl())
}

pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(MEDIA_VECTOR.decl()) {
        rows::check_row(MEDIA_VECTOR, at, value)
    } else {
        rows::check_row(MEDIA_DEVICE, at, value)
    }
}

pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    rows::restore_parts(dbs, txn, &opened, check, rows::no_join)
}
