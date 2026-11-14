//! The shared-act family's rows that hold a person's id, for the actor-erase
//! test: execution receipts, outcome notices, erase asks, pending acts, and
//! started and matured notices.

use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Result, Vault};

const TABLES: [(&str, SideTable<String, Vec<u8>, Raw>); 6] = [
    ("receipt", SideTable::new(&side_table::SHARED_ACT_RECEIPT)),
    ("outcome", SideTable::new(&side_table::SHARED_ACT_OUTCOME)),
    (
        "erase_ask",
        SideTable::new(&side_table::SHARED_ACT_ERASE_ASK),
    ),
    (
        "pending_act",
        SideTable::new(&side_table::SHARED_ACT_RECORD),
    ),
    ("started", SideTable::new(&side_table::SHARED_ACT_EVENT)),
    ("matured", SideTable::new(&side_table::SHARED_ACT_MATURED)),
];

/// `table:key` of each shared-act family row whose key or stored bytes hold
/// `person`'s hex.
///
/// # Errors
/// The scan's.
#[doc(hidden)]
pub fn rows_naming(vault: &Vault, person: EntityId) -> Result<Vec<String>> {
    let hex = person.to_hex();
    let txn = vault.store.env.read_txn()?;
    let mut found = Vec::new();
    for (name, table) in &TABLES {
        for (key, row) in table.scan(&vault.store, &txn)? {
            if key.contains(&hex) || row.windows(hex.len()).any(|bytes| bytes == hex.as_bytes()) {
                found.push(format!("{name}:{key}"));
            }
        }
    }
    Ok(found)
}
