//! The checkpoint getter of source-audience bindings (fix list row 17455):
//! each row's binding and its hold go exactly under the entity tree of the
//! row their key names, so an erase of that row reaches them with it.
//! Neither names an actor: a binding names a policy, which is a side-table
//! id and not an entity row, and a hold names only why it holds. So nothing
//! is split, and no part depends on a policy: a policy is never an owner
//! that opens or does not open, so a dependency on one would protect
//! nothing.
//!
//! The policies a row carries (SOURCE_AUDIENCE_DERIVED) stay in the image
//! as they were: their monotone floor (Refuse(ImageEntities)) is compared
//! with the live vault before any compartment opens, so a sealed set would
//! read as absent there and refuse an unchanged restore. They join this
//! getter once that comparison reads the opened parts (fix list row 20941).
//!
//! A restore writes each row back exactly as it was sealed, once its own
//! table's codec reads it and its key names the compartment's own row. It
//! never rewrites a value, merges a set or replays a policy, and every
//! table keeps its restore class (Engine L04, 6 Nov 22:30). The policies,
//! their events and the thread index stay under the vault-wide seal: no
//! compartment holds them yet (fix list row 17208 stays open for a
//! per-owner one). The birth marks, policy wakes and policy windows are
//! live working state that no compartment holds.
#![allow(
    dead_code,
    reason = "KS7-2b and KS7-5 call the getters; CHECKPOINT_PAYLOADS_ENABLED is false until KS7-6"
)]

use heed::{RoTxn, RwTxn};

use super::{HELD, RECORDS};
use crate::EntityId;
use crate::error::Result;
use crate::side_table::{SideKey, SideTableDecl};
use crate::store::ManifestDbs;
use crate::store::checkpoint_payload::rows::{
    self, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator,
};

/// Every binding and hold in `txn`, each under the row its key names.
pub(crate) fn capture(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Captured> {
    let mut out = Captured::default();
    for row in rows::typed_rows(dbs, txn, RECORDS, &mut out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    for row in rows::typed_rows(dbs, txn, HELD, &mut out)? {
        out.exact(OwnerRef::entity(&row.key), row.at, row.bytes);
    }
    Ok(out)
}

/// The tables this getter places.
fn tables() -> [&'static SideTableDecl; 2] {
    [RECORDS.decl(), HELD.decl()]
}

fn owns(at: &RowLocator) -> bool {
    tables().into_iter().any(|decl| at.in_table(decl))
}

/// The bundle framing of `rows`' source-audience parts.
pub(crate) fn bytes_for_owner(rows: &OwnerRows) -> Result<Vec<u8>> {
    rows::frame_owner(rows, owns)
}

fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    if at.in_table(RECORDS.decl()) {
        rows::check_row(RECORDS, at, value)
    } else if at.in_table(HELD.decl()) {
        rows::check_row(HELD, at, value)
    } else {
        Err(rows::bad_part())
    }
}

/// The row a part's key names: its owner.
fn row_of(at: &RowLocator) -> Option<OwnerRef> {
    tables()
        .into_iter()
        .find(|decl| at.in_table(decl))
        .and_then(|decl| at.key.strip_prefix(decl.prefix))
        .and_then(EntityId::decode_key)
        .map(|row| OwnerRef::entity(&row))
}

/// Puts `opened`'s source-audience rows back exactly, each one its table's
/// codec reads and whose key names the compartment's own row.
pub(crate) fn restore_in_txn(
    dbs: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    opened: OpenedOwnerRows,
) -> Result<Restored> {
    let (subtype, owner32) = (opened.subtype, opened.owner32);
    rows::restore_parts(
        dbs,
        txn,
        &opened,
        |at, value| {
            check(at, value)?;
            match row_of(at) {
                Some(row) if row.subtype == subtype && row.owner32 == owner32 => Ok(()),
                _ => Err(rows::bad_part()),
            }
        },
        rows::no_join,
    )
}
