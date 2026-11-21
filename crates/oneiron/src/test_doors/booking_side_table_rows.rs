//! The raw rows of every side table a booking keeps
//! (BOOKING-TOKEN-DIGEST-ROW-NO-DOOR, Engine TASK 16 Nov 11:44), so the
//! `booking_token_digest_rows` test proves canon ARCH-0062:114, "A booking's
//! stored metadata holds only digests of its hold and checkout tokens, never
//! their usable values". Read-only: every declared `vault_meta` table in the
//! booking keyspace, each row's key past its table prefix and its value
//! bytes, undecoded.

use crate::error::Result;
use crate::side_table::{self, SideDb, SideTableDbs, SideTableDecl};
use crate::vault::Vault;

/// The booking keyspace: every booking table's prefix starts with one of
/// these, the lifecycle's own and the publication write stage alike.
const BOOKING_KEYSPACE: [&[u8]; 2] = [b"booking.", b"booking:"];

/// One booking side-table row, undecoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookingSideTableRow {
    /// The table, by its catalogue name.
    pub table: &'static str,
    /// The key bytes past the table prefix.
    pub key: Vec<u8>,
    /// The stored value bytes.
    pub value: Vec<u8>,
}

fn booking_tables() -> impl Iterator<Item = &'static SideTableDecl> {
    side_table::declared().filter(|decl| {
        decl.db == SideDb::VaultMeta
            && BOOKING_KEYSPACE
                .iter()
                .any(|keyspace| decl.prefix.starts_with(keyspace))
    })
}

/// The catalogue name of every table the row listing below walks.
#[must_use]
pub fn booking_side_table_names() -> Vec<&'static str> {
    booking_tables().map(|decl| decl.name).collect()
}

/// Every row of every booking side table, in catalogue order.
///
/// # Errors
///
/// Storage errors.
pub fn booking_side_table_rows(vault: &Vault) -> Result<Vec<BookingSideTableRow>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    for decl in booking_tables() {
        for row in vault
            .store
            .side_vault_meta()
            .prefix_iter(&rtxn, decl.prefix)?
        {
            let (key, value) = row?;
            rows.push(BookingSideTableRow {
                table: decl.name,
                key: key[decl.prefix.len()..].to_vec(),
                value: value.to_vec(),
            });
        }
    }
    Ok(rows)
}
