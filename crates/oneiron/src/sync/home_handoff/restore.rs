//! FIX 5661 C2b: a restore over a live vault keeps every registered table's
//! rows live. For each table a home move carries, the live vault's rows and
//! absences win over the image's: the table's live keys now, and the
//! image's keys it manages ([`super::HomeTable::manages`]). An old export
//! never comes back over later spend. A table whose live rows do not read or
//! decode while the set is built keeps its own restore class, so the image
//! wins where that class is content, and the restore notes it (Engine 10-20
//! 19:3x): nothing new refuses. A restore that re-elects its home moves it
//! only from the image's designation, never a real move, so the head the
//! restore kept live keeps its move ([`keep_move_through`]).

use std::collections::{BTreeMap, BTreeSet};

use super::{home_tables, store};
use crate::Vault;
use crate::error::Result;
use crate::side_table::SideDb;

/// What a restore over the live vault keeps live for the registered tables.
pub(crate) struct HomeManaged {
    /// The full stored keys by database name: each table's live keys now,
    /// and the keys it manages among the image's rows.
    pub(crate) keys: BTreeMap<&'static str, BTreeSet<Vec<u8>>>,
    /// The tables whose live rows did not read or decode: each keeps its own
    /// restore class.
    pub(crate) unreadable: Vec<&'static str>,
}

/// The rows a restore over `vault` keeps live for the registered tables,
/// over `image`, the restore image's rows by database. A table whose live
/// rows fail to read or decode here names none and is listed unreadable.
///
/// # Errors
///
/// A read transaction on the live vault that does not open.
pub(crate) fn restore_managed_keys(
    vault: &Vault,
    image: &BTreeMap<String, Vec<(Vec<u8>, Vec<u8>)>>,
) -> Result<HomeManaged> {
    let txn = vault.store.env.read_txn()?;
    let mut managed = HomeManaged {
        keys: BTreeMap::new(),
        unreadable: Vec::new(),
    };
    for table in home_tables() {
        let database = match table.database() {
            SideDb::VaultMeta => "vault_meta",
            SideDb::SyncState => "sync_state",
        };
        let rows = image.get(database).map_or(&[][..], Vec::as_slice);
        let keys = table.live_keys(vault, &txn).and_then(|mut keys| {
            keys.extend(table.manages(vault, &txn, rows)?);
            Ok(keys)
        });
        match keys {
            Ok(keys) => managed.keys.entry(database).or_default().extend(keys),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    table = table.table_id(),
                    "a home table's live rows did not read; it restores from the image"
                );
                managed.unreadable.push(table.table_id());
            }
        }
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
