//! The owner's approval each outstanding machine link stores (L10-16, M-1
//! keep), read and rewritten as plain JSON, so the `machine_link_stored_row`
//! test can put a link back in the shape main stored it in and prove that it
//! still redeems. Every assertion is in the test.

use serde_json::{Map, Value};

use crate::error::Result;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::vault::Vault;

/// The outstanding pairing links, each row read as the JSON it is stored as.
const PAIRING_PENDING_JSON: SideTable<String, Value, LegacyJson> =
    SideTable::new(&side_table::AUTHORITY_PAIRING_PENDING);

/// The owner's approval (the row's `machine` object) of every outstanding
/// machine link, in key order.
///
/// # Errors
///
/// Storage errors.
pub fn pending_machine_approvals(vault: &Vault) -> Result<Vec<Map<String, Value>>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(PAIRING_PENDING_JSON
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .filter_map(|(_, row)| match row.get("machine") {
            Some(Value::Object(machine)) => Some(machine.clone()),
            _ => None,
        })
        .collect())
}

/// Rewrites the owner's approval of every outstanding machine link with
/// `rewrite`, stores each row back under its key, and returns how many it
/// rewrote.
///
/// # Errors
///
/// Storage errors.
pub fn rewrite_pending_machine_approvals(
    vault: &Vault,
    rewrite: impl Fn(&mut Map<String, Value>),
) -> Result<usize> {
    vault.with_write_txn(|wtxn| {
        let rows = PAIRING_PENDING_JSON.scan(&vault.store, wtxn)?;
        let mut rewritten = 0;
        for (key, mut row) in rows {
            let Some(Value::Object(machine)) = row.get_mut("machine") else {
                continue;
            };
            rewrite(machine);
            PAIRING_PENDING_JSON.put(&vault.store, wtxn, &key, &row)?;
            rewritten += 1;
        }
        Ok(rewritten)
    })
}
