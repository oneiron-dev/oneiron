//! An agent dispatch's attempt row as a row-held response of a checkpoint
//! image (FIX 7115, KS-2B1): whether the row rests opaque, what an image
//! carries of it, and who owns its text. The dispatch target's text erase
//! and its owner are the engine's, called through the store's attempt
//! operations.

use crate::entity_id::EntityId;
use crate::store::attempt_id::AttemptId;
use crate::store::attempt_payload_route::attempt_payload_family;
use crate::store::attempt_record::AttemptRecord;
use crate::store::attempt_record_codec::{decode_record, encode_record};
use crate::store::{ResponseCarriage, ResponseScan, StoreAttemptOperations};

/// The queue row `key` holding `raw`, decoded; `None` for one that does not.
fn record_of(key: &[u8], raw: &[u8]) -> Option<AttemptRecord> {
    decode_record(raw, AttemptId::from_bytes(key).ok()?).ok()
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
pub(crate) fn attempt_payload_scan(
    operations: &dyn StoreAttemptOperations,
    key: &[u8],
    raw: &[u8],
) -> ResponseScan {
    let Some(mut record) = record_of(key, raw) else {
        return ResponseScan::opaque_row();
    };
    match operations.erase_dispatch_payload_text_target(&mut record) {
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
pub(crate) fn attempt_payload_owners(
    operations: &dyn StoreAttemptOperations,
    key: &[u8],
    raw: &[u8],
) -> Vec<EntityId> {
    record_of(key, raw)
        .and_then(|record| operations.dispatch_payload_actor(&record))
        .into_iter()
        .collect()
}
