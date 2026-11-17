//! The shared-act family's rows that hold a person's id, for the actor-erase
//! test: execution receipts, outcome notices, erase asks, pending acts, and
//! started and matured notices. It also overwrites one pending act's stored
//! payload past the start door's plan check, so a test holds a legacy row a
//! start refuses today.

use crate::federation::PendingAuthorityAct;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Error, Result, Vault};

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

const PENDING_ACTS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SHARED_ACT_RECORD);

/// Overwrites act `id`'s stored payload past the start door's plan check, so
/// a test holds a legacy row a start refuses today.
///
/// # Errors
/// No act `id` is stored, its row does not decode, or the store refuses the
/// write.
#[doc(hidden)]
pub fn overwrite_pending_act_payload(vault: &Vault, id: &str, payload: Vec<u8>) -> Result<()> {
    vault.with_write_txn(|txn| {
        let raw = PENDING_ACTS
            .get(&vault.store, txn, &id.to_owned())?
            .ok_or(Error::InvariantViolation("no pending act with that id"))?;
        let mut act: PendingAuthorityAct = serde_json::from_slice(&raw)
            .map_err(|_| Error::InvariantViolation("the stored act does not decode"))?;
        act.payload = payload;
        let row = serde_json::to_vec(&act)
            .map_err(|_| Error::InvariantViolation("the act does not encode"))?;
        PENDING_ACTS.put(&vault.store, txn, &id.to_owned(), &row)
    })
}

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
