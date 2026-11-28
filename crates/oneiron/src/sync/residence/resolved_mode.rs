//! The residence mode this machine's own sync connection last resolved (sync all or sync what
//! it opened): one device-local row (`rs:resolved`), never synced. The put transaction and the
//! read gate cannot see the in-memory mode (the vault's `HomeSearchSlot`, in
//! `sync/connection/home_search.rs`), so they read this stored row instead. The one writer is the
//! resolution in `sync/connection/home_search.rs`, which records at each resolution a connection
//! applies; no row reads as not opened. Key: (). Value: one byte, 1 = Opened, 2 = All. Engine
//! ANSWER PR1-OPENED-COLD-SOURCE-MODE = A (28 Nov).

use crate::side_table::{self, Raw, SideTable};
use crate::sync::client::SyncResidenceMode;

/// The stored resolved-mode row (`rs:resolved`). Key: (). Value: `[1]` opened, `[2]` sync all.
const RESOLVED_MODE: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_RESOLVED_MODE);

/// Records `mode`, the residence mode just resolved for this machine's own sync connection.
/// Writes the one byte only when it differs, so a residence refresh that resolves the same mode
/// writes nothing. Every write of the row goes through this function.
pub(crate) fn record_resolved_device_residence_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    mode: SyncResidenceMode,
) -> crate::Result<()> {
    let want = vec![match mode {
        SyncResidenceMode::Opened => 1,
        SyncResidenceMode::All => 2,
    }];
    if RESOLVED_MODE.get(store, txn, &())?.as_deref() == Some(want.as_slice()) {
        return Ok(());
    }
    RESOLVED_MODE.put(store, txn, &(), &want)
}

/// Whether this machine's own sync connection last resolved sync-what-it-opened: true only when
/// the row holds exactly `[1]`. No row, `[2]`, or any other bytes read as not opened.
pub(crate) fn device_residence_opened_in_txn(
    dbs: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
) -> crate::Result<bool> {
    Ok(RESOLVED_MODE
        .get(dbs, txn, &())?
        .is_some_and(|bytes| bytes == [1]))
}
