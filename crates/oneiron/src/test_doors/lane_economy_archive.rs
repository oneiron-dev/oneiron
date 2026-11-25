//! Doors for `tests/archive_lane_economy_tables_retained.rs` (FIX
//! LANE-ECONOMY-TABLES-ARCHIVE-CLASS): the lane economy's live side rows, and the rows of them
//! the whole-vault export carries as retained copies.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::Vault;
use crate::side_table::{self, SideTableDecl};

/// The lane economy's five side tables, by declared name.
pub const LANE_ECONOMY_TABLES: [&str; 5] = [
    "EXPERIMENT_ARM",
    "EXPERIMENT_ARM_UNIT",
    "GPU_LINE",
    "GPU_LINE_PERIOD",
    "LANE_ECONOMY_INTENT",
];

/// The declaration of the lane-economy table named `table`.
fn lane_economy_decl(table: &str) -> crate::Result<&'static SideTableDecl> {
    [
        &side_table::EXPERIMENT_ARM,
        &side_table::EXPERIMENT_ARM_UNIT,
        &side_table::GPU_LINE,
        &side_table::GPU_LINE_PERIOD,
        &side_table::LANE_ECONOMY_INTENT,
    ]
    .into_iter()
    .find(|decl| decl.name == table)
    .ok_or_else(|| crate::Error::InvalidConfig(format!("{table} is not a lane-economy side table")))
}

/// The live rows of `table`, as (stored key after the declared prefix, value) in key order.
///
/// # Errors
///
/// A name that is none of [`LANE_ECONOMY_TABLES`]; the store's.
#[doc(hidden)]
pub fn live_rows(vault: &Vault, table: &str) -> crate::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let decl = lane_economy_decl(table)?;
    let rtxn = vault.store.env.read_txn()?;
    decl.iter_raw(&vault.store, &rtxn)?.collect()
}

/// The (source key, source value) tuples of `table` this vault's whole-vault export carries as
/// retained rows, live and inert, in physical key order: the export's own collection.
///
/// # Errors
///
/// The collection's.
#[doc(hidden)]
pub fn exported_rows(vault: &Vault, table: &str) -> crate::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    crate::batch::export::archive_retained_side_rows::exported_retained_tuples(vault, table)
}
