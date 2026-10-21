//! An agent dispatch's payload text in checkpoint images (FIX 7115, KEY
//! STORE = A): its attempt row is a row-held response of its own (KS-2B1),
//! sealed whole under a body instance its dispatch target's erase retires.
//!
//! An image carries the row as an erase of its target leaves it: the same
//! deterministic rewrite ([`erase_dispatch_payload_text`]) with every other
//! input member, the envelope's parent and every row field kept. A live
//! instance lands the exact row; a retired one leaves the text-free row,
//! which every strict reader reads. Only the dispatch target owns the text,
//! never its requester or a definition guessed from elsewhere.

use std::borrow::Cow;

use super::super::encoding::{decode_record, encode_record};
use super::super::types::{AttemptId, AttemptRecord};
use super::{dispatch_payload_actor, erase_dispatch_payload_text};
use crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE;
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// The queue row `key` holding `raw`, decoded; `None` for one that does not.
fn record_of(key: &[u8], raw: &[u8]) -> Option<AttemptRecord> {
    decode_record(raw, AttemptId::from_bytes(key).ok()?).ok()
}

/// Whether the queue row `key` holding `raw` is a Dreamer agent dispatch's:
/// its family, even once an erase took its text.
pub(crate) fn attempt_payload_family(key: &[u8], raw: &[u8]) -> bool {
    record_of(key, raw).is_some_and(|record| {
        record.kind == DREAMER_RUNNER_ATTEMPT_KIND
            && decode_dreamer_attempt_payload(&record.payload)
                .is_ok_and(|payload| payload.attempt_type == AGENT_DISPATCH_ATTEMPT_TYPE)
    })
}

/// The row as an erase of its target leaves it, the stub an image carries
/// in its place: `None` when it holds no text to carry, or does not decode
/// or rewrite, and so travels as it is.
pub(crate) fn attempt_payload_stub(key: &[u8], raw: &[u8]) -> Option<Vec<u8>> {
    let mut record = record_of(key, raw)?;
    match erase_dispatch_payload_text(&mut record) {
        Ok(true) => encode_record(&record).ok(),
        Ok(false) | Err(_) => None,
    }
}

/// Who owns the row's text: its dispatch target, the AGENT_DEF the dispatch
/// runs as. None for a row that names none.
pub(crate) fn attempt_payload_owners(key: &[u8], raw: &[u8]) -> Vec<EntityId> {
    record_of(key, raw)
        .and_then(|record| dispatch_payload_actor(&record))
        .into_iter()
        .collect()
}

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
        crate::vault_cleanup::refresh_archived_attempt_in_txn(store, wtxn, id, &before, stub)?;
    }
    Ok(())
}
