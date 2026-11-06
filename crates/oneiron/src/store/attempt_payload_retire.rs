//! Retiring an attempt row's payload text in place: the row takes its
//! text-free form when the body instance it was sealed under is retired,
//! and its cleanup mark follows it when it bound the row as it stood. The
//! store's checkpoint activation retires the row; the attempt queue's
//! response carriage (`attempt_queue::payload_erase::response`) builds the
//! text-free form.
use std::borrow::Cow;

use crate::error::Result;
use crate::store::Store;
use crate::store::attempt_id::AttemptId;

/// Leaves the live row `key` its text-free form `stub` in `wtxn`: an
/// activation's prune of a row whose instance its source retired. Its
/// archive mark follows it when it bound the row as it stood.
///
/// # Errors
///
/// Storage errors, and a key that is no attempt's.
pub(crate) fn retire_attempt_payload_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    key: &[u8],
    stub: &[u8],
) -> Result<()> {
    let id = AttemptId::from_bytes(key)?;
    let before = store.attempt_records.get(wtxn, key)?.map(Cow::into_owned);
    store.attempt_records.put(wtxn, key, stub)?;
    if let Some(before) = before {
        crate::store::attempt_archive_mark::refresh_archived_attempt_in_txn(
            store, wtxn, id, &before, stub,
        )?;
    }
    Ok(())
}
