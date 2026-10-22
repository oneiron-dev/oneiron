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
//!
//! A dispatch's row is recognized by a routing probe that asks no strict
//! validator: its version, its kind and its payload's attempt type. One that
//! the strict reader then refuses, or whose text-free form does not encode,
//! is carried whole as an opaque response, and its retired form is the
//! erased marker, which the strict reader answers `ResponseErased` (FIX
//! 9390). No other row of the queue is taken for a dispatch's.

use std::borrow::Cow;

use serde::Deserialize;

use super::super::encoding::{decode_record, encode_record};
use super::super::types::{ATTEMPT_RECORD_VERSION, AttemptId, AttemptRecord};
use super::{dispatch_payload_actor, erase_dispatch_payload_text};
use crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE;
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{ResponseCarriage, ResponseScan, Store, is_opaque_erased};

/// The Dreamer attempt payload's pinned key naming its attempt type.
const PAYLOAD_ATTEMPT_TYPE_KEY: &str = "job_type";

/// What the routing probe reads of a queue row: its kind and payload, past
/// every validator the strict reader runs.
#[derive(Deserialize)]
struct Routing {
    kind: String,
    payload: Vec<u8>,
}

/// The queue row `key` holding `raw`, decoded; `None` for one that does not.
fn record_of(key: &[u8], raw: &[u8]) -> Option<AttemptRecord> {
    decode_record(raw, AttemptId::from_bytes(key).ok()?).ok()
}

/// Whether `raw` reads, by the routing probe alone, as a Dreamer agent
/// dispatch's row: its record version, the Dreamer kind, and a payload map
/// naming the agent dispatch attempt type.
fn routed_dispatch(raw: &[u8]) -> bool {
    let Some((&version, body)) = raw.split_first() else {
        return false;
    };
    let Ok(routing) = rmp_serde::from_slice::<Routing>(body) else {
        return false;
    };
    version == ATTEMPT_RECORD_VERSION
        && routing.kind == DREAMER_RUNNER_ATTEMPT_KIND
        && matches!(
            rmpv::decode::read_value(&mut routing.payload.as_slice()),
            Ok(rmpv::Value::Map(entries)) if entries.iter().any(|(name, value)| {
                name.as_str() == Some(PAYLOAD_ATTEMPT_TYPE_KEY)
                    && value.as_str() == Some(AGENT_DISPATCH_ATTEMPT_TYPE)
            })
        )
}

/// Whether the queue row `key` holding `raw` is a Dreamer agent dispatch's:
/// its family, even once an erase took its text, and the erased marker an
/// opaque one's retirement leaves (FIX 9390).
pub(crate) fn attempt_payload_family(key: &[u8], raw: &[u8]) -> bool {
    AttemptId::from_bytes(key).is_ok() && (is_opaque_erased(raw) || routed_dispatch(raw))
}

/// Whether the queue row `key` holding `raw` is an opaque dispatch row: the
/// erased marker, or a row the routing probe takes for a dispatch's that
/// the strict reader refuses. It lands, and is carried, exactly as it rests.
pub(crate) fn attempt_row_opaque(key: &[u8], raw: &[u8]) -> bool {
    attempt_payload_family(key, raw) && record_of(key, raw).is_none()
}

/// What a checkpoint carries of a dispatch's row: the whole row, the row as
/// an erase of its target leaves it the stub an image carries in its place.
/// No response when it holds no text; a row the strict reader refuses, or
/// whose text-free form does not rewrite or encode, is carried whole as an
/// opaque response.
pub(crate) fn attempt_payload_scan(key: &[u8], raw: &[u8]) -> ResponseScan {
    let Some(mut record) = record_of(key, raw) else {
        return ResponseScan::opaque_row();
    };
    match erase_dispatch_payload_text(&mut record) {
        Ok(true) => encode_record(&record).map_or_else(
            |_| ResponseScan::opaque_row(),
            |stub| ResponseScan::Decoded(ResponseCarriage::whole(stub)),
        ),
        Ok(false) => ResponseScan::NotResponse,
        Err(_) => ResponseScan::opaque_row(),
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
