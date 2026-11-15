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

use super::{HELD, RECORDS};
use crate::EntityId;
use crate::side_table::SideKey;
use crate::store::checkpoint_payload::rows::descriptor::{
    Adapter, Capture, Check, ExactTable, Join, Restore,
};
use crate::store::checkpoint_payload::rows::{OwnerRef, RowLocator};

/// Every binding and hold, each whole under the row its key names. A
/// restored part must be a row its own table's codec reads, whose key names
/// the compartment's own row.
pub(crate) static ADAPTER: Adapter = Adapter {
    tables: &[
        &ExactTable {
            table: RECORDS,
            owner: OwnerRef::entity,
        },
        &ExactTable {
            table: HELD,
            owner: OwnerRef::entity,
        },
    ],
    capture: Capture::ByTable,
    check: Check::ByTable,
    row_owner: Some(row_of),
    join: Join::NoSplit,
    restore: Restore::Parts,
};

/// The row a part's key names: its owner.
fn row_of(at: &RowLocator) -> Option<OwnerRef> {
    [RECORDS.decl(), HELD.decl()]
        .into_iter()
        .find(|decl| at.in_table(decl))
        .and_then(|decl| at.key.strip_prefix(decl.prefix))
        .and_then(EntityId::decode_key)
        .map(|row| OwnerRef::entity(&row))
}
