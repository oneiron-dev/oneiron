//! Moved from `crates/oneiron/src/edit_roundtrip/judgment.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::edit_roundtrip::ops::CellValue;
use oneiron_base::error::Error;
use oneiron_store::blob_artifact::office_address::CellRef;
use oneiron_store::model_decision::EvidenceVersion;
use oneiron_wake_contract::llm::decision::types::TypedDecision;
use serde::Deserialize;
use serde::Serialize;

/// One answer's target and its decision. `value` is the cell the decision's
/// answer writes; `None` is an abstention, which writes nothing and is not
/// a negative answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SheetCellAnswer {
    pub cell: CellRef,
    pub before: Option<CellValue>,
    pub value: Option<CellValue>,
    /// The decide() call's full decision and receipt.
    pub decision: TypedDecision,
    /// For a folder column: the file this row answers for, at the version
    /// read. Keep refuses the column when that file has moved.
    #[serde(default)]
    pub source: Option<EvidenceVersion>,
    /// The version of what the call read: the workbook for a row, the file
    /// for a folder column. With the evidence hash it names the revision
    /// the answer was judged against.
    #[serde(default)]
    pub judged_version: Option<u64>,
    /// For a folder column: the file's live body when it was read, so an
    /// edit to it never exported withdraws the answer (FIX 2115).
    #[serde(default)]
    pub judged_live: Option<oneiron_store::typed_body::live_pin::LivePin>,
}

/// What each row's call read beside its own cells: the row's cells in
/// columns `first_col..=last_col` (the answer column aside) and the header
/// row's. An answer whose read cells change under it is withdrawn at Keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SheetRowReads {
    pub first_col: u32,
    pub last_col: u32,
    pub header_row: Option<u32>,
}

pub fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}
