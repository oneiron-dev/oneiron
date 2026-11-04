//! One kind's payloads, emptied for an erase (FIX 9775): the attempts of a
//! kind whose payload names an erased party keep their row and every field
//! but the payload, in every state and retry generation, so no address or
//! party it carried stays in the queue. An emptied payload decodes as no
//! payload of its kind, so its executor fails a still-queued row unsent.

use crate::error::Result;
use crate::store::Store;

use super::encoding::{decode_record, encode_record};
use super::types::{AttemptId, AttemptRecord};

/// Empties, in the erase's transaction, the payload of every attempt of
/// `kind` whose payload `names` picks, and moves each row's archive mark and
/// run snapshot with it. A row that does not decode, or whose payload is
/// already empty, stays as it is.
///
/// # Errors
///
/// Storage errors, and a matching row that does not encode.
pub(crate) fn erase_kind_payloads_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    kind: &str,
    names: impl Fn(&[u8]) -> bool,
) -> Result<()> {
    let mut rewrites: Vec<(Vec<u8>, AttemptRecord)> = Vec::new();
    for row in store.attempt_records.iter(txn)? {
        let (key, raw) = row?;
        let Ok(id) = AttemptId::from_bytes(&key) else {
            continue;
        };
        let Ok(mut record) = decode_record(&raw, id) else {
            continue;
        };
        if record.kind != kind || record.payload.is_empty() || !names(&record.payload) {
            continue;
        }
        record.payload.clear();
        rewrites.push((raw.into_owned(), record));
    }
    let mut rewritten = Vec::with_capacity(rewrites.len());
    for (before, record) in rewrites {
        let after = encode_record(&record)?;
        store
            .attempt_records
            .put(txn, record.id.as_bytes(), &after)?;
        crate::vault_cleanup::refresh_archived_attempt_in_txn(
            store, txn, record.id, &before, &after,
        )?;
        rewritten.push((record.id, before, after));
    }
    crate::vault_cleanup::erase_attempt_references_in_txn(store, txn, &rewritten)
}
