//! Point reads of one attempt row inside the caller's transaction: the
//! decoded row, and whether a worker still holds its lease. Neither opens a
//! transaction of its own; the attempt queue's inherent methods of the same
//! names forward here.

use crate::error::Result;
use crate::store::Store;
use crate::store::attempt_id::AttemptId;
use crate::store::attempt_record::AttemptRecord;
use crate::store::attempt_record_codec::decode_record;
use crate::store::attempt_state::AttemptState;

/// Reads attempt `id` in `txn`: `None` when no row is stored under it,
/// otherwise the strictly decoded row.
pub(crate) fn get_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
) -> Result<Option<AttemptRecord>> {
    get_with_source_in_txn(store, txn, id, |_, _| {})
}

/// The same point read with its physical key and full stored value lent to
/// an observer before decoding. These bytes are provenance, not read authority.
pub(crate) fn get_with_source_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
    source: impl FnOnce(AttemptId, Option<&[u8]>),
) -> Result<Option<AttemptRecord>> {
    let raw = store.attempt_records.get(txn, id.as_bytes())?;
    source(id, raw.as_deref());
    let Some(raw) = raw else {
        return Ok(None);
    };
    decode_record(&raw, id).map(Some)
}

/// Whether `lease_owner` still holds `id`'s lease at `attempt_count`: the
/// row is leased, to that owner, at that lease generation, and no
/// cleanup or redirect took it since. A caller that writes on a claimed
/// try's behalf checks it in its own writer first (FIX 5088).
pub(crate) fn holds_lease_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
    lease_owner: &str,
    attempt_count: u32,
) -> Result<bool> {
    Ok(get_in_txn(store, txn, id)?.is_some_and(|record| {
        record.state == AttemptState::Leased
            && record.lease_owner.as_deref() == Some(lease_owner)
            && record.attempt_count == attempt_count
    }))
}
