//! The Coach triage's erased payload and dedupe move as one native queue rewrite.
use super::super::{AttemptQueue, AttemptRecord};
use crate::dreamer_runner::maintenance::coach::COACH_HOST_QUEUE_KIND;
use crate::dreamer_runner::{decode_dreamer_attempt_payload, encode_dreamer_attempt_payload};
use crate::store::Store;
use crate::{EntityId, Result};

fn erased_payload_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &AttemptRecord,
    only_evidence: Option<EntityId>,
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
        only_evidence,
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
    Ok(match erased_payload_in_txn(store, txn, record, None)? {
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
    if let Some(payload) = erased_payload_in_txn(store, txn, record, None)? {
        AttemptQueue::from_store(store).delete_owned_dedupe_entries_for_record(txn, record)?;
        apply(record, payload);
    }
    Ok(())
}

/// Fresh-marker hard paths retain the accepted writer and select only its
/// evidence. The physical scan leaves every other payload family untouched.
pub(crate) fn erase_feedback_triage_as_in_txn(
    erase: &mut crate::deletion::ActorErasureWriter<'_, '_>,
) -> Result<()> {
    let (vault, txn, evidence) = erase.parts();
    let store = &vault.store;
    let mut rewrites = Vec::new();
    for row in store.attempt_records.iter(txn)? {
        let (key, raw) = row?;
        let Ok(id) = super::super::AttemptId::from_bytes(&key) else {
            continue;
        };
        let Ok(mut record) = super::decode_record(&raw, id) else {
            continue;
        };
        if let Some(payload) = erased_payload_in_txn(store, txn, &record, Some(evidence))?
            && apply(&mut record, payload)
        {
            crate::store::attempt_manifest::erase_manifest_revision_pins(
                &mut record.manifest,
                |id| *id == evidence,
            );
            rewrites.push((raw.into_owned(), record));
        }
    }
    super::flush_rewrites_in_txn(store, txn, rewrites)
}
