//! Served pack operations, including explicit default skill imports.

use super::owner_routes::OwnerTable;

pub(super) mod defaults;

pub(super) fn owner_table() -> OwnerTable {
    defaults::owner_table()
}
