//! Moved from `crates/oneiron/src/edit_roundtrip/inspect.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::blob_artifact::office_address::OfficeFormat;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::collections::HashMap;

/// One sheet in workbook order (1-based `index`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SheetSummary {
    pub name: String,
    pub index: u32,
}

/// A best-effort cross-sheet formula dependency edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossSheetDep {
    pub from_sheet: String,
    pub to_sheet: String,
}

/// The inspect-first structure summary produced before any edit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructureSummary {
    pub format: OfficeFormat,
    pub sheets: Vec<SheetSummary>,
    pub defined_names: Vec<String>,
    pub has_pivots: bool,
    pub has_charts: bool,
    pub has_macros: bool,
    pub cross_sheet_dependencies: Vec<CrossSheetDep>,
    /// Parts classified unknown/unsupported — the passthrough set.
    pub unknown_parts: Vec<String>,
}
