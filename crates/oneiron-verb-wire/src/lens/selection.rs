//! Moved from `crates/oneiron/src/lens/selection.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_lens_wire::lens::atom::GeneratedUiResultSetActionEvent;
use oneiron_lens_wire::lens::wire_ids::LensAtomId;
use oneiron_lens_wire::lens::wire_ids::LensHandleName;
use oneiron_lens_wire::lens::wire_ids::LensRenderId;
use serde::Deserialize;
use serde::Serialize;

/// Half-open Unicode scalar offsets. A supplied version is an echo to check,
/// never a version the engine is asked to trust or read instead of the live one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensSelectionRange {
    pub start: usize,
    pub end: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensSelectRequest {
    pub card_id: LensRenderId,
    pub atom_id: LensAtomId,
    pub handle: LensHandleName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<LensSelectionRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensSelectionResolveRequest {
    pub card_id: LensRenderId,
    pub selection_ref: String,
}

/// Cursor bytes, not a copy of the selected text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensSelectedSpan {
    pub start: usize,
    pub end: usize,
    pub version: Vec<u8>,
    pub start_cursor: Vec<u8>,
    pub end_cursor: Vec<u8>,
}

/// Row ids are echoes of this rendered result set. Each selected ref must name
/// the corresponding engine-issued selection, in rendered order; select-all
/// instead names the rendered predicate's one QueryResult selection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensResultSetActionRequest {
    pub event: GeneratedUiResultSetActionEvent,
    pub selected: Vec<String>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensResultSetActionResult {
    pub outcome: serde_json::Value,
    pub read_receipt: oneiron_contracts::claim::ScopedReadReceipt,
}
