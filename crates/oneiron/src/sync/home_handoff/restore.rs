//! FIX 5661 C2b: a restore over a live vault keeps every registered table's
//! rows live. For each table a home move carries, the live vault's rows and
//! absences win over the image's: the table's live keys now, and the
//! image's keys it manages ([`super::HomeTable::manages`]). An old export
//! never comes back over later spend. A restore that re-elects its home
//! moves it only from the image's designation, never a real move, so the
//! head the restore kept live keeps its move ([`keep_move_through`]).

use std::collections::{BTreeMap, BTreeSet};

use super::{home_tables, store};
use crate::Vault;
use crate::error::Result;
use crate::side_table::SideDb;

/// The full stored keys a restore over `vault` keeps live for the registered
/// tables, by database name: each table's live keys now, and the keys it
/// manages among `image`, the restore image's rows by database.
///
/// # Errors
///
/// Storage errors reading the live vault's rows.
pub(crate) fn restore_managed_keys(
    vault: &Vault,
    image: &BTreeMap<String, Vec<(Vec<u8>, Vec<u8>)>>,
) -> Result<BTreeMap<&'static str, BTreeSet<Vec<u8>>>> {
    let txn = vault.store.env.read_txn()?;
    let mut managed: BTreeMap<&'static str, BTreeSet<Vec<u8>>> = BTreeMap::new();
    for table in home_tables() {
        let database = match table.database() {
            SideDb::VaultMeta => "vault_meta",
            SideDb::SyncState => "sync_state",
        };
        let rows = image.get(database).map_or(&[][..], Vec::as_slice);
        let keys = managed.entry(database).or_default();
        keys.extend(table.live_keys(vault, &txn)?);
        keys.extend(table.manages(vault, &txn, rows)?);
    }
    Ok(managed)
}

/// Runs `elect`, a restore's re-election of its home, and then puts back
/// the move and route the carrier's head held before it, where the election
/// recorded another: the restore kept the live vault's head, and moving off
/// the image's designation is no move.
///
/// # Errors
///
/// `elect`'s error; storage errors.
pub(crate) fn keep_move_through<T>(vault: &Vault, elect: impl FnOnce() -> Result<T>) -> Result<T> {
    let (request, route) = {
        let txn = vault.store.env.read_txn()?;
        let head = store::head_in_txn(vault, &txn)?;
        (head.request, head.route)
    };
    let elected = elect()?;
    vault.with_write_txn(|txn| {
        let mut head = store::head_in_txn(vault, txn)?;
        if head.request == request && head.route == route {
            return Ok(());
        }
        head.request = request;
        head.route = route;
        store::put_head_in_txn(vault, txn, &head)
    })?;
    Ok(elected)
}
