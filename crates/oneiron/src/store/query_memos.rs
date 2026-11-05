//! Core half of `store::query_memos`: its store-layer items live in `oneiron_store::query_memos` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::query_memos::*;

use super::query_memo_codec::{canonical_json_bytes, hex_lower, parse_entity_ref};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};
use crate::store::{ResponseCarriage, ResponseScan};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value};

/// Cached match-evaluator verdict for one `(query, entity, evidence)` triple.
pub(crate) const MEMOS: SideTable<VerdictMemoKey, VerdictMemoRow, Raw> =
    SideTable::new(&side_table::SAVED_QUERY_MEMO);

/// Who owns the memo row `value`: its query, candidate and sources; just the
/// query and candidate for a row that does not know its sources; none for a
/// row that does not decode.
pub(crate) fn memo_owners(value: &[u8]) -> Vec<EntityId> {
    let Ok(row) = MEMOS.decode_value(value) else {
        return Vec::new();
    };
    owners(&row).unwrap_or_else(|| vec![row.key.query_ref, row.key.entity_ref])
}

/// What a checkpoint carries of the memo row `value`: the whole row, and
/// nothing once retired, as a captured request is carried (its retirement
/// drops the row, in images and live alike). A row that does not decode is
/// carried whole as an opaque response (FIX 6227).
pub(crate) fn memo_carriage(value: &[u8]) -> ResponseScan {
    if MEMOS.decode_value(value).is_err() {
        return ResponseScan::opaque_row();
    }
    ResponseScan::Decoded(ResponseCarriage {
        keep: 0,
        stub: Vec::new(),
        retired: 0,
    })
}
