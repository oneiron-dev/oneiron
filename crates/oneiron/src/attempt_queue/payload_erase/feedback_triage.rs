//! The Coach triage's erased payload and dedupe move as one native queue rewrite.
use super::super::{AttemptQueue, AttemptRecord};
use crate::Result;
use crate::dreamer_runner::maintenance::coach::COACH_HOST_QUEUE_KIND;
use crate::dreamer_runner::{decode_dreamer_attempt_payload, encode_dreamer_attempt_payload};
use crate::store::Store;

fn erased_payload_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &AttemptRecord,
) -> Result<Option<Vec<u8>>> {
    if record.kind != COACH_HOST_QUEUE_KIND {
        return Ok(None);
    }
    let Ok(mut payload) = decode_dreamer_attempt_payload(&record.payload) else {
        return Ok(None);
    };
    let Some(input) = crate::feedback::erased_queue_input_in_txn(
        store,
        txn,
        &payload.attempt_type,
        &payload.input,
    )?
    else {
        return Ok(None);
    };
    payload.input = input;
    encode_dreamer_attempt_payload(&payload).map(Some)
}

fn apply(record: &mut AttemptRecord, payload: Vec<u8>) -> bool {
    let changed = record.payload != payload
        || record.dedupe_key.is_some()
        || record.dedupe_actor_ref.is_some();
    record.payload = payload;
    record.dedupe_key = None;
    record.dedupe_actor_ref = None;
    changed
}

/// The source pass gathers rewrites while its read cursor is open. The one
/// native flush retires the original row's owned dedupe before writing it.
pub(super) fn rewrite_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &mut AttemptRecord,
) -> Result<bool> {
    Ok(match erased_payload_in_txn(store, txn, record)? {
        Some(payload) => apply(record, payload),
        None => false,
    })
}

/// A stale clone clears the same fields the caller will use after encoding.
/// On an I/O error, the transaction fails rather than reintroducing erased data.
pub(in crate::attempt_queue) fn scrub_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    record: &mut AttemptRecord,
) -> Result<()> {
    if let Some(payload) = erased_payload_in_txn(store, txn, record)? {
        AttemptQueue::from_store(store).delete_owned_dedupe_entries_for_record(txn, record)?;
        apply(record, payload);
    }
    Ok(())
}
