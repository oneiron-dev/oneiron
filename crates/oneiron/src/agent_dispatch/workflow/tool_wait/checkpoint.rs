//! Checkpoint payload projection for the workflow transcript pointer and
//! settled meter. The actor owns the whole row; known sources and the room
//! are dependencies, independently of whether the source set is complete.

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};

use super::{TABLE, body_owner, key};
use crate::Result;
use crate::side_table::SideKey;
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

/// Positive native source dependencies for this capture's dedicated body
/// owners. A malformed or foreign binding does not classify another owner.
pub(crate) fn body_dependencies(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
) -> Result<BTreeMap<crate::EntityId, Vec<crate::EntityId>>> {
    let mut dependencies = BTreeMap::new();
    for found in TABLE.iter_raw_from(dbs, txn, &[])? {
        let (raw_key, bytes) = found?;
        let Some(row_key) = <crate::EntityId as SideKey>::decode_key(&raw_key) else {
            continue;
        };
        let Ok(row) = TABLE.decode_value(&bytes) else {
            continue;
        };
        let Some(binding) = row.binding() else {
            continue;
        };
        if row_key != key(row.attempt)? || binding.body_owner != body_owner(row.attempt)? {
            continue;
        }
        let mut sources = vec![binding.actor];
        for source in binding.known_sources.into_iter().chain(binding.room) {
            if !sources.contains(&source) {
                sources.push(source);
            }
        }
        dependencies.insert(binding.body_owner, sources);
    }
    for (owner, sources) in super::body_sources::body_dependencies(dbs, txn)? {
        let known = dependencies.entry(owner).or_default();
        for source in sources {
            if !known.contains(&source) {
                known.push(source);
            }
        }
    }
    Ok(dependencies)
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
