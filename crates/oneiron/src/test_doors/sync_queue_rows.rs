//! Door for `tests/sync_outbox.rs` (FIX row SYNC-OUTBOX-READ-PRUNES-ROWS),
//! mounted inside `sync::queue` so it reaches a stored update row by the
//! queue's own key codec. Reached as `oneiron::test_doors::sync_queue_rows`
//! (re-exported there); compiled only under `oneiron_test_support`.

use std::borrow::Cow;

use super::SyncQueue;
use super::codec::encode_update_key;

/// Overwrites the stored bytes of queued update `seq` with `value`, raw and
/// unchecked, as a damaged row reads back.
///
/// # Errors
///
/// The store's write fault, told as text.
pub fn put_raw_update_row(queue: &SyncQueue, seq: u64, value: &[u8]) -> Result<(), String> {
    let store = &queue.vault.store;
    let mut wtxn = store.env.write_txn().map_err(|err| err.to_string())?;
    store
        .sync_queue
        .put(&mut wtxn, &encode_update_key(seq), value)
        .map_err(|err| err.to_string())?;
    wtxn.commit().map_err(|err| err.to_string())
}

/// The stored bytes of queued update `seq`, raw, or `None` when no row holds
/// its key.
///
/// # Errors
///
/// The store's read fault, told as text.
pub fn raw_update_row(queue: &SyncQueue, seq: u64) -> Result<Option<Vec<u8>>, String> {
    let store = &queue.vault.store;
    let rtxn = store.env.read_txn().map_err(|err| err.to_string())?;
    store
        .sync_queue
        .get(&rtxn, &encode_update_key(seq))
        .map(|row| row.map(Cow::into_owned))
        .map_err(|err| err.to_string())
}
