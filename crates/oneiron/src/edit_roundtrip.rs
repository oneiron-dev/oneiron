//! ARTL-3 (OF-368 D5): agent edit round-trip — code-session pipeline.
//!
//! An agent implementing a commented change on a foreign office file (xlsx
//! first) runs in a code-session (doc 11: own=Wasmtime, foreign=microVM)
//! against a **copy** of the artifact's current bytes. The output is a
//! *retained output* — `(new blob bytes + [`EditManifest`])` — that touches
//! nothing until settled. This module owns the host-side orchestration and the
//! canonical [`EditManifest`]; settlement (append the version, mint the
//! receipt) is ARTL-4 and out of scope here.
//!
//! # Fidelity law (Grok DR 2026-07-07)
//!
//! Nothing round-trips 100%. The pipeline is **minimal-mutation + passthrough**:
//! it touches only supported elements and preserves unknown XML parts
//! byte-for-byte. The passthrough and corruption gates run in the engine (the
//! `opc` submodule) against the bytes the session produced, so the gate never
//! trusts the tool that wrote them.
//!
//! # Four mandatory stages
//!
//! 1. **Inspect-first** — the `inspect` stage summarizes structure (sheets, defined
//!    names, pivots/charts/macros presence, cross-sheet dependency map) before
//!    any edit. SpreadsheetBench evidence: skipping this is the dominant agent
//!    failure mode, so it always runs.
//! 2. **Targeted edit** — the agent's [`EditPlan`] is applied through the
//!    [`EditSession`] seam via narrow verbs ([`EditOp`]). In production the
//!    session library is Python openpyxl (`keep_vba=True, data_only=False`);
//!    umya-spreadsheet (Rust) and protobi/exceljs (JS) are recorded alternates.
//! 3. **Recalc** — when inputs/formulas changed, [`EditSession::recalc`]
//!    refreshes cached formula values. In production this is LibreOffice
//!    headless (a session-image dependency); HyperFormula/`formulas` is the
//!    recorded in-process fallback.
//! 4. **Corruption-check validation** — the `validate` stage runs an automated
//!    open/verify plus a passthrough diff. A failed check yields
//!    [`EditOutcome::Rejected`] and never reaches the proposal stage.
//!
//! # External-binary seam
//!
//! openpyxl and LibreOffice are NOT available in CI and are NOT repo
//! dependencies (D10 licensing wall: repo code is Apache/MIT only; openpyxl
//! lives in session images). They sit behind the [`EditSession`] trait so the
//! architecture is present but the whole gate passes with a mock. The pipeline
//! logic, manifest, inspection, and validation are pure Rust and fully tested
//! in CI against a fixture session.
//!
//! # Reconciliation seams
//!
//! * **ARTL-2 (anchored comments, ONE-1552)** consumes [`EditManifest::anchor_effects`]
//!   to replay row/column shifts, range moves, and sheet renames against its
//!   `(sheet, A1-range)` anchors. This module keeps its manifest self-contained
//!   and does not import ARTL-2 types; whichever PR merges second reconciles.
//! * **ARTL-4 (settle/receipts)** consumes an [`EditProposal`]:
//!   [`EditProposal::agent_run_provenance`] yields the
//!   [`BlobVersionProvenance::AgentRun`] to append, and [`EditManifest::to_msgpack`]
//!   the manifest bytes to receipt.

mod opc;

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::blob_artifact::BlobVersionProvenance;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use opc::{OpcPackage, PartClass};

/// Serialization version for [`EditManifest`]. Bump on any incompatible change
/// to the op vocabulary or manifest shape.
pub const EDIT_MANIFEST_SCHEMA_VERSION: u32 = 1;

const XLSX_MEDIA_TYPE: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
const XLSM_MEDIA_TYPE: &str = "application/vnd.ms-excel.sheet.macroEnabled.12";
const DOCX_MEDIA_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const PPTX_MEDIA_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.presentationml.presentation";

// ---------------------------------------------------------------------------
// Format + cell addressing
// ---------------------------------------------------------------------------

/// Office Open XML family the pipeline operates on. P1 is xlsx; docx/pptx are
/// staged (D9) and already addressable so the manifest is format-stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfficeFormat {
    Xlsx,
    Docx,
    Pptx,
}

impl OfficeFormat {
    /// Maps an artifact media type to its format, erroring on anything the
    /// pipeline does not yet handle.
    pub fn from_media_type(media_type: &str) -> Result<Self> {
        match media_type {
            XLSX_MEDIA_TYPE | XLSM_MEDIA_TYPE => Ok(Self::Xlsx),
            DOCX_MEDIA_TYPE => Ok(Self::Docx),
            PPTX_MEDIA_TYPE => Ok(Self::Pptx),
            _ => Err(Error::EditRoundtripFailed(
                "media type is not a supported office format",
            )),
        }
    }

    /// The required "spine" part whose absence in an output means the package
    /// was gutted.
    #[must_use]
    pub const fn spine_part(self) -> &'static str {
        match self {
            Self::Xlsx => "xl/workbook.xml",
            Self::Docx => "word/document.xml",
            Self::Pptx => "ppt/presentation.xml",
        }
    }
}

/// The axis a structural op operates on, for anchor re-mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Axis {
    Row,
    Column,
}

/// A single cell address, 1-based on both axes (A1 == col 1, row 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellRef {
    pub col: u32,
    pub row: u32,
}

impl CellRef {
    #[must_use]
    pub const fn new(col: u32, row: u32) -> Self {
        Self { col, row }
    }

    /// Parses an A1-style reference such as `"AB12"`.
    pub fn parse(text: &str) -> Result<Self> {
        let split = text
            .find(|c: char| c.is_ascii_digit())
            .ok_or(Error::EditRoundtripFailed("cell reference missing a row"))?;
        if split == 0 {
            return Err(Error::EditRoundtripFailed(
                "cell reference missing a column",
            ));
        }
        let (letters, digits) = text.split_at(split);
        let col = letters_to_column(letters)?;
        let row: u32 = digits
            .parse()
            .map_err(|_| Error::EditRoundtripFailed("cell reference row is not a number"))?;
        if row == 0 {
            return Err(Error::EditRoundtripFailed(
                "cell reference row must be >= 1",
            ));
        }
        Ok(Self { col, row })
    }

    /// Renders the reference in A1 notation.
    #[must_use]
    pub fn to_a1(self) -> String {
        format!("{}{}", column_to_letters(self.col), self.row)
    }
}

/// A rectangular range, inclusive of both corners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeRef {
    pub start: CellRef,
    pub end: CellRef,
}

impl RangeRef {
    #[must_use]
    pub const fn new(start: CellRef, end: CellRef) -> Self {
        Self { start, end }
    }

    /// Parses an `"A1:B2"` range.
    pub fn parse(text: &str) -> Result<Self> {
        let (start, end) = text
            .split_once(':')
            .ok_or(Error::EditRoundtripFailed("range reference missing ':'"))?;
        Ok(Self {
            start: CellRef::parse(start)?,
            end: CellRef::parse(end)?,
        })
    }

    /// Renders the range in A1 notation.
    #[must_use]
    pub fn to_a1(self) -> String {
        format!("{}:{}", self.start.to_a1(), self.end.to_a1())
    }
}

fn column_to_letters(mut index: u32) -> String {
    // `index` is a validated 1-based column (see `validate_ops`), so 0 never
    // reaches the renderer and no placeholder is emitted.
    debug_assert!(index >= 1, "column index must be 1-based");
    let mut letters = Vec::new();
    while index > 0 {
        let rem = ((index - 1) % 26) as u8;
        letters.push((b'A' + rem) as char);
        index = (index - 1) / 26;
    }
    letters.iter().rev().collect()
}

fn letters_to_column(letters: &str) -> Result<u32> {
    if letters.is_empty() {
        return Err(Error::EditRoundtripFailed("column reference is empty"));
    }
    let mut col: u32 = 0;
    for ch in letters.chars() {
        if !ch.is_ascii_alphabetic() {
            return Err(Error::EditRoundtripFailed(
                "column reference has a non-letter",
            ));
        }
        let value = u32::from(ch.to_ascii_uppercase() as u8 - b'A') + 1;
        col = col
            .checked_mul(26)
            .and_then(|c| c.checked_add(value))
            .ok_or(Error::EditRoundtripFailed("column reference overflow"))?;
    }
    Ok(col)
}

/// Enforces the 1-based cell/range/axis invariant across a plan's ops before
/// any of them reaches a session or the renderer. [`CellRef::new`] and
/// [`RangeRef::new`] are unchecked constructors, so a caller can build an op
/// addressing column/row 0 or an inverted range; such an op names a
/// non-existent cell and would render a bogus address, so it is rejected as an
/// invalid manifest here rather than acted on.
fn validate_ops(ops: &[EditOp]) -> Result<()> {
    for op in ops {
        match op {
            EditOp::SetCell { cell, .. } => check_cell(*cell)?,
            EditOp::SetRange { range, writes, .. } => {
                check_range(*range)?;
                for write in writes {
                    check_cell(write.cell)?;
                }
            }
            EditOp::AddFormulaColumn { column, .. } => ensure_one_based(*column)?,
            EditOp::InsertRows { at, .. }
            | EditOp::DeleteRows { at, .. }
            | EditOp::InsertColumns { at, .. }
            | EditOp::DeleteColumns { at, .. } => ensure_one_based(*at)?,
            EditOp::MoveRange { from, to, .. } => {
                check_range(*from)?;
                check_cell(*to)?;
            }
            EditOp::AddSheet { .. } | EditOp::RemoveSheet { .. } | EditOp::RenameSheet { .. } => {}
        }
    }
    Ok(())
}

fn check_cell(cell: CellRef) -> Result<()> {
    ensure_one_based(cell.col)?;
    ensure_one_based(cell.row)
}

fn check_range(range: RangeRef) -> Result<()> {
    check_cell(range.start)?;
    check_cell(range.end)?;
    if range.start.col > range.end.col || range.start.row > range.end.row {
        return Err(Error::InvalidEditManifest(
            "edit op range is inverted; start must be at or above-left of end",
        ));
    }
    Ok(())
}

fn ensure_one_based(index: u32) -> Result<()> {
    if index == 0 {
        return Err(Error::InvalidEditManifest(
            "edit op uses a 0 index; cells, ranges, and axis positions are 1-based",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Values and the op vocabulary
// ---------------------------------------------------------------------------

/// A typed cell value. Formulas carry their expression and, once recalculated,
/// the cached value the viewer displays (xlsx stores cached values inline).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellValue {
    Blank,
    Number(f64),
    Text(String),
    Bool(bool),
    Formula {
        expr: String,
        cached: Option<Box<CellValue>>,
    },
    Error(String),
}

impl CellValue {
    fn render(&self) -> String {
        match self {
            Self::Blank => "<blank>".to_owned(),
            Self::Number(n) => n.to_string(),
            Self::Text(t) => format!("\"{t}\""),
            Self::Bool(b) => b.to_string(),
            Self::Formula { expr, .. } => format!("={expr}"),
            Self::Error(e) => format!("#{e}"),
        }
    }
}

/// One cell write inside a range edit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CellWrite {
    pub cell: CellRef,
    pub before: Option<CellValue>,
    pub after: CellValue,
}

/// The canonical edit-op vocabulary. Each op carries enough to (a) exactly
/// describe the mutation (before/after on value writes), (b) drive anchor
/// re-mapping via [`EditOp::anchor_effect`] (structural ops), and (c) render as
/// a semantic diff via [`EditOp::render`] (D7: the manifest *is* the diff).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EditOp {
    /// Write a single cell.
    SetCell {
        sheet: String,
        cell: CellRef,
        before: Option<CellValue>,
        after: CellValue,
    },
    /// Write a rectangular range (the `update_cell_range` verb).
    SetRange {
        sheet: String,
        range: RangeRef,
        writes: Vec<CellWrite>,
    },
    /// Append a computed column (the `add_formula_column` verb). `formula` is
    /// the per-row template; `header`, when present, labels the first row.
    AddFormulaColumn {
        sheet: String,
        column: u32,
        header: Option<String>,
        formula: String,
    },
    /// Insert `count` rows before 1-based row `at`.
    InsertRows { sheet: String, at: u32, count: u32 },
    /// Delete `count` rows starting at 1-based row `at`.
    DeleteRows { sheet: String, at: u32, count: u32 },
    /// Insert `count` columns before 1-based column `at`.
    InsertColumns { sheet: String, at: u32, count: u32 },
    /// Delete `count` columns starting at 1-based column `at`.
    DeleteColumns { sheet: String, at: u32, count: u32 },
    /// Move a range to a new top-left anchor.
    MoveRange {
        sheet: String,
        from: RangeRef,
        to: CellRef,
    },
    /// Add a new empty sheet.
    AddSheet { name: String },
    /// Remove a sheet and its part.
    RemoveSheet { name: String },
    /// Rename a sheet (references and anchors follow).
    RenameSheet { from: String, to: String },
}

impl EditOp {
    /// The sheet this op targets, when it names one.
    #[must_use]
    pub fn sheet(&self) -> Option<&str> {
        match self {
            Self::SetCell { sheet, .. }
            | Self::SetRange { sheet, .. }
            | Self::AddFormulaColumn { sheet, .. }
            | Self::InsertRows { sheet, .. }
            | Self::DeleteRows { sheet, .. }
            | Self::InsertColumns { sheet, .. }
            | Self::DeleteColumns { sheet, .. }
            | Self::MoveRange { sheet, .. } => Some(sheet),
            Self::AddSheet { name } | Self::RemoveSheet { name } => Some(name),
            Self::RenameSheet { from, .. } => Some(from),
        }
    }

    /// Whether this op can change cell values or formula inputs, so a recalc
    /// stage is warranted. Adding an empty sheet cannot.
    #[must_use]
    pub const fn may_affect_values(&self) -> bool {
        !matches!(self, Self::AddSheet { .. })
    }

    /// Whether this op changes package structure (row/column/sheet topology)
    /// rather than only cell contents. Structural ops are refused in
    /// minimal-mutation mode, where preserved pivot/chart/macro parts index
    /// into a grid the op would shift out from under them. Mirrors the ops that
    /// carry an [`EditOp::anchor_effect`].
    #[must_use]
    pub const fn is_structural(&self) -> bool {
        matches!(
            self,
            Self::InsertRows { .. }
                | Self::DeleteRows { .. }
                | Self::InsertColumns { .. }
                | Self::DeleteColumns { .. }
                | Self::MoveRange { .. }
                | Self::RemoveSheet { .. }
                | Self::RenameSheet { .. }
        )
    }

    /// The anchor-remapping effect ARTL-2 replays, when this op moves content.
    /// Pure value writes return `None` — they never shift an anchor.
    #[must_use]
    pub fn anchor_effect(&self) -> Option<AnchorEffect> {
        match self {
            Self::InsertRows { sheet, at, count } => Some(AnchorEffect::Shift(StructuralShift {
                sheet: sheet.clone(),
                axis: Axis::Row,
                at: *at,
                delta: i64::from(*count),
            })),
            Self::DeleteRows { sheet, at, count } => Some(AnchorEffect::Shift(StructuralShift {
                sheet: sheet.clone(),
                axis: Axis::Row,
                at: *at,
                delta: -i64::from(*count),
            })),
            Self::InsertColumns { sheet, at, count } => {
                Some(AnchorEffect::Shift(StructuralShift {
                    sheet: sheet.clone(),
                    axis: Axis::Column,
                    at: *at,
                    delta: i64::from(*count),
                }))
            }
            Self::DeleteColumns { sheet, at, count } => {
                Some(AnchorEffect::Shift(StructuralShift {
                    sheet: sheet.clone(),
                    axis: Axis::Column,
                    at: *at,
                    delta: -i64::from(*count),
                }))
            }
            Self::MoveRange { sheet, from, to } => Some(AnchorEffect::RangeMoved {
                sheet: sheet.clone(),
                from: *from,
                to: *to,
            }),
            Self::RenameSheet { from, to } => Some(AnchorEffect::SheetRenamed {
                from: from.clone(),
                to: to.clone(),
            }),
            Self::RemoveSheet { name } => Some(AnchorEffect::SheetRemoved { name: name.clone() }),
            Self::SetCell { .. }
            | Self::SetRange { .. }
            | Self::AddFormulaColumn { .. }
            | Self::AddSheet { .. } => None,
        }
    }

    /// A one-line semantic diff rendering of this op.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::SetCell {
                sheet,
                cell,
                before,
                after,
            } => {
                let before = before
                    .as_ref()
                    .map_or_else(|| "<empty>".to_owned(), CellValue::render);
                format!(
                    "set {sheet}!{}: {before} -> {}",
                    cell.to_a1(),
                    after.render()
                )
            }
            Self::SetRange {
                sheet,
                range,
                writes,
            } => format!(
                "set range {sheet}!{} ({} cells)",
                range.to_a1(),
                writes.len()
            ),
            Self::AddFormulaColumn {
                sheet,
                column,
                header,
                formula,
            } => {
                let header = header.as_deref().unwrap_or("<none>");
                format!(
                    "add formula column {sheet}!{} (header {header}): ={formula}",
                    column_to_letters(*column)
                )
            }
            Self::InsertRows { sheet, at, count } => {
                format!("insert {count} row(s) at {sheet}!row {at}")
            }
            Self::DeleteRows { sheet, at, count } => {
                format!("delete {count} row(s) at {sheet}!row {at}")
            }
            Self::InsertColumns { sheet, at, count } => format!(
                "insert {count} column(s) at {sheet}!col {}",
                column_to_letters(*at)
            ),
            Self::DeleteColumns { sheet, at, count } => format!(
                "delete {count} column(s) at {sheet}!col {}",
                column_to_letters(*at)
            ),
            Self::MoveRange { sheet, from, to } => {
                format!("move {sheet}!{} -> {}", from.to_a1(), to.to_a1())
            }
            Self::AddSheet { name } => format!("add sheet {name}"),
            Self::RemoveSheet { name } => format!("remove sheet {name}"),
            Self::RenameSheet { from, to } => format!("rename sheet {from} -> {to}"),
        }
    }
}

/// A self-contained descriptor of how a structural op shifts an axis. ARTL-2
/// maps this onto its own anchor locators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralShift {
    pub sheet: String,
    pub axis: Axis,
    /// 1-based index where the insert/delete begins.
    pub at: u32,
    /// Signed magnitude: positive for insert, negative for delete.
    pub delta: i64,
}

/// The anchor-remapping effect of a structural op — the ARTL-2 reconciliation
/// surface. Kept independent of ARTL-2's own op-view on purpose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorEffect {
    Shift(StructuralShift),
    RangeMoved {
        sheet: String,
        from: RangeRef,
        to: CellRef,
    },
    SheetRenamed {
        from: String,
        to: String,
    },
    SheetRemoved {
        name: String,
    },
}

// ---------------------------------------------------------------------------
// Warnings + mutation mode
// ---------------------------------------------------------------------------

/// Whether the pipeline ran in full-edit or minimal-mutation mode. Heavy
/// pivot/chart/macro workbooks force [`MutationMode::Minimal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationMode {
    Full,
    Minimal,
}

/// Stable warning codes surfaced on the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningCode {
    HeavyPivotMinimalMutation,
    ChartsPresentMinimalMutation,
    MacrosPresentMinimalMutation,
    SessionReported,
}

/// A pipeline warning: a stable code plus human detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditWarning {
    pub code: WarningCode,
    pub detail: String,
}

impl EditWarning {
    #[must_use]
    pub fn new(code: WarningCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// The canonical manifest
// ---------------------------------------------------------------------------

/// The canonical cell-level edit manifest (D7: the manifest is the diff and the
/// re-anchoring input). Self-contained and versioned for durable storage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EditManifest {
    pub schema_version: u32,
    pub format: OfficeFormat,
    /// The ops actually applied by the session — no phantom ops, no missing
    /// ops (the session reports exactly what it did).
    pub ops: Vec<EditOp>,
    /// The OPC parts that legitimately changed, observed by diffing the input
    /// and output packages (authoritative, not derived from the ops).
    pub touched_parts: BTreeSet<String>,
    pub mutation_mode: MutationMode,
    pub warnings: Vec<EditWarning>,
}

impl EditManifest {
    /// The anchor-remapping effects, in op order, for ARTL-2 replay.
    #[must_use]
    pub fn anchor_effects(&self) -> Vec<AnchorEffect> {
        self.ops.iter().filter_map(EditOp::anchor_effect).collect()
    }

    /// One diff line per op (D7 semantic diff; the viewer never re-parses two
    /// binaries).
    #[must_use]
    pub fn render_diff(&self) -> Vec<String> {
        self.ops.iter().map(EditOp::render).collect()
    }

    /// Field-name-tagged MessagePack encoding for durable storage (ARTL-4).
    pub fn to_msgpack(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| Error::InvalidEditManifest("edit manifest failed to encode"))
    }

    /// Decodes a manifest from [`EditManifest::to_msgpack`] bytes.
    pub fn from_msgpack(bytes: &[u8]) -> Result<Self> {
        let manifest: Self = rmp_serde::from_slice(bytes)
            .map_err(|_| Error::InvalidEditManifest("edit manifest failed to decode"))?;
        if manifest.schema_version != EDIT_MANIFEST_SCHEMA_VERSION {
            return Err(Error::InvalidEditManifest(
                "edit manifest schema version is unsupported",
            ));
        }
        Ok(manifest)
    }
}

// ---------------------------------------------------------------------------
// Inspection (stage 1)
// ---------------------------------------------------------------------------

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

/// Runs the mandatory inspect-first stage over an already-parsed package.
#[must_use]
fn inspect(package: &OpcPackage, format: OfficeFormat) -> StructureSummary {
    let has_pivots = package
        .names()
        .any(|n| n.starts_with("xl/pivotTables/") || n.starts_with("xl/pivotCache/"));
    let has_charts = package.names().any(|n| n.starts_with("xl/charts/"));
    let has_macros = package.contains("xl/vbaProject.bin");

    let sheets = scan_sheets(package);
    let defined_names = scan_defined_names(package);
    let cross_sheet_dependencies = scan_cross_sheet_deps(package, &sheets);
    let unknown_parts = package
        .names()
        .filter(|n| opc::classify(n) == PartClass::Unknown)
        .map(str::to_owned)
        .collect();

    StructureSummary {
        format,
        sheets,
        defined_names,
        has_pivots,
        has_charts,
        has_macros,
        cross_sheet_dependencies,
        unknown_parts,
    }
}

fn mutation_mode_for(summary: &StructureSummary) -> (MutationMode, Vec<EditWarning>) {
    let mut warnings = Vec::new();
    if summary.has_pivots {
        warnings.push(EditWarning::new(
            WarningCode::HeavyPivotMinimalMutation,
            "workbook contains pivot tables; limiting to minimal-mutation passthrough",
        ));
    }
    if summary.has_charts {
        warnings.push(EditWarning::new(
            WarningCode::ChartsPresentMinimalMutation,
            "workbook contains charts; limiting to minimal-mutation passthrough",
        ));
    }
    if summary.has_macros {
        warnings.push(EditWarning::new(
            WarningCode::MacrosPresentMinimalMutation,
            "workbook contains VBA macros; limiting to minimal-mutation passthrough",
        ));
    }
    let mode = if warnings.is_empty() {
        MutationMode::Full
    } else {
        MutationMode::Minimal
    };
    (mode, warnings)
}

fn scan_sheets(package: &OpcPackage) -> Vec<SheetSummary> {
    let Some(workbook) = package.part("xl/workbook.xml") else {
        return Vec::new();
    };
    let xml = String::from_utf8_lossy(workbook);
    scan_tag_attr(&xml, "<sheet", "name")
        .into_iter()
        .enumerate()
        .map(|(i, name)| SheetSummary {
            name,
            index: (i as u32) + 1,
        })
        .collect()
}

fn scan_defined_names(package: &OpcPackage) -> Vec<String> {
    let Some(workbook) = package.part("xl/workbook.xml") else {
        return Vec::new();
    };
    let xml = String::from_utf8_lossy(workbook);
    scan_tag_attr(&xml, "<definedName", "name")
}

fn scan_cross_sheet_deps(package: &OpcPackage, sheets: &[SheetSummary]) -> Vec<CrossSheetDep> {
    let name_by_part = worksheet_name_by_part(package);
    // BTreeSet dedupes (replacing the O(n) `Vec::contains`) and yields a stable
    // ordering regardless of part iteration order.
    let mut deps: BTreeSet<(String, String)> = BTreeSet::new();
    for part in package.parts() {
        // Resolve this worksheet part to its sheet name via the workbook
        // relationships; fall back to the positional `sheetN.xml == Nth sheet`
        // heuristic only when the rels join did not cover it (e.g. rels absent).
        let Some(from_name) = name_by_part
            .get(&part.name)
            .map(String::as_str)
            .or_else(|| {
                worksheet_ordinal(&part.name)
                    .and_then(|ordinal| sheets.iter().find(|sheet| sheet.index == ordinal))
                    .map(|sheet| sheet.name.as_str())
            })
        else {
            continue;
        };
        let xml = String::from_utf8_lossy(&part.data);
        for formula in extract_formulas(&xml) {
            // A cross-sheet reference always contains '!'; skip the common
            // same-sheet formula before the O(sheets) comparison.
            if !formula.contains('!') {
                continue;
            }
            for other in sheets {
                if other.name == from_name {
                    continue;
                }
                if formula_references_sheet(&formula, &other.name) {
                    deps.insert((from_name.to_owned(), other.name.clone()));
                }
            }
        }
    }
    deps.into_iter()
        .map(|(from_sheet, to_sheet)| CrossSheetDep {
            from_sheet,
            to_sheet,
        })
        .collect()
}

/// Maps each worksheet part path to its workbook sheet name by joining
/// `xl/_rels/workbook.xml.rels` (relationship id -> Target) with
/// `xl/workbook.xml`'s `<sheet name=.. r:id=..>` entries — the authoritative
/// binding, since sheet part names need not match workbook order. Empty when
/// either part is absent, so the caller falls back to the positional heuristic.
fn worksheet_name_by_part(package: &OpcPackage) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let (Some(workbook), Some(rels)) = (
        package.part("xl/workbook.xml"),
        package.part("xl/_rels/workbook.xml.rels"),
    ) else {
        return out;
    };
    let rels_xml = String::from_utf8_lossy(rels);
    let id_to_target: HashMap<String, String> =
        scan_tag_attr_pairs(&rels_xml, "<Relationship", "Id", "Target")
            .into_iter()
            .collect();
    let workbook_xml = String::from_utf8_lossy(workbook);
    for (name, rid) in scan_tag_attr_pairs(&workbook_xml, "<sheet", "name", "r:id") {
        if let Some(target) = id_to_target.get(&rid) {
            out.insert(join_xl_target(target), name);
        }
    }
    out
}

/// Resolves a `xl/_rels/workbook.xml.rels` Target (relative to `xl/`, or
/// absolute from the package root) to a full part path.
fn join_xl_target(target: &str) -> String {
    target
        .strip_prefix('/')
        .map_or_else(|| format!("xl/{target}"), str::to_owned)
}

fn worksheet_ordinal(name: &str) -> Option<u32> {
    let stem = name
        .strip_prefix("xl/worksheets/sheet")?
        .strip_suffix(".xml")?;
    stem.parse().ok()
}

fn formula_references_sheet(formula: &str, sheet: &str) -> bool {
    formula.contains(&format!("{sheet}!")) || formula.contains(&format!("'{sheet}'!"))
}

/// Extracts the inline expression from every `<f>` / `<f ...attrs>` element.
/// Shared and array formulas carry attributes (`<f t="shared" si="0">`), so we
/// match the tag prefix, skip to the end of the open tag, then read to `</f>`.
/// A self-closing `<f .../>` (a shared-formula reference with no inline text)
/// yields nothing.
fn extract_formulas(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(idx) = rest.find("<f") {
        let after = &rest[idx + 2..];
        // The char after "<f" must end the tag name, so `<font>`/`<fill>` and
        // similar are not mistaken for a formula element.
        let is_f_element = after
            .chars()
            .next()
            .is_none_or(|c| c == '>' || c == '/' || c.is_ascii_whitespace());
        if !is_f_element {
            rest = after;
            continue;
        }
        let Some(open_end) = after.find('>') else {
            break;
        };
        if after[..open_end].ends_with('/') {
            rest = &after[open_end + 1..];
            continue;
        }
        let content = &after[open_end + 1..];
        let Some(close) = content.find("</f>") else {
            break;
        };
        out.push(content[..close].to_owned());
        rest = &content[close + "</f>".len()..];
    }
    out
}

fn scan_tag_attr(xml: &str, tag: &str, attr: &str) -> Vec<String> {
    let needle = format!("{attr}=\"");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(pos) = rest.find(tag) {
        let after_tag = &rest[pos + tag.len()..];
        let tag_end = after_tag.find('>').unwrap_or(after_tag.len());
        let body = &after_tag[..tag_end];
        if let Some(value) = attr_value(body, &needle) {
            out.push(value);
        }
        rest = &after_tag[tag_end..];
    }
    out
}

/// Like [`scan_tag_attr`] but reads two attributes from the same tag, keeping
/// only tags that carry both (order-independent).
fn scan_tag_attr_pairs(xml: &str, tag: &str, attr1: &str, attr2: &str) -> Vec<(String, String)> {
    let needle1 = format!("{attr1}=\"");
    let needle2 = format!("{attr2}=\"");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(pos) = rest.find(tag) {
        let after_tag = &rest[pos + tag.len()..];
        let tag_end = after_tag.find('>').unwrap_or(after_tag.len());
        let body = &after_tag[..tag_end];
        if let (Some(v1), Some(v2)) = (attr_value(body, &needle1), attr_value(body, &needle2)) {
            out.push((v1, v2));
        }
        rest = &after_tag[tag_end..];
    }
    out
}

/// Reads a double-quoted attribute value from a tag body given the search
/// needle `name="` (already including the opening quote).
fn attr_value(tag_body: &str, needle: &str) -> Option<String> {
    let start = tag_body.find(needle)? + needle.len();
    let end = tag_body[start..].find('"')?;
    Some(tag_body[start..start + end].to_owned())
}

// ---------------------------------------------------------------------------
// The external-binary seam (stages 2 + 3)
// ---------------------------------------------------------------------------

/// The office file passed across the [`EditSession`] seam: the raw bytes plus
/// the pipeline's decomposition of them.
#[derive(Debug, Clone)]
pub struct OfficeDoc {
    pub format: OfficeFormat,
    pub bytes: Vec<u8>,
    package: OpcPackage,
}

impl OfficeDoc {
    fn new(format: OfficeFormat, bytes: Vec<u8>, package: OpcPackage) -> Self {
        Self {
            format,
            bytes,
            package,
        }
    }

    /// Read-only view of the decomposed parts, for a session that reasons in
    /// Rust (a session shelling out to Python uses [`OfficeDoc::bytes`]).
    pub fn parts(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.package
            .parts()
            .iter()
            .map(|p| (p.name.as_str(), p.data.as_slice()))
    }
}

/// The agent's requested edit.
#[derive(Debug, Clone)]
pub struct EditPlan {
    pub ops: Vec<EditOp>,
    /// Force recalc on/off; `None` auto-detects from the applied ops.
    pub request_recalc: Option<bool>,
}

impl EditPlan {
    #[must_use]
    pub fn new(ops: Vec<EditOp>) -> Self {
        Self {
            ops,
            request_recalc: None,
        }
    }

    fn needs_recalc(&self, applied: &[EditOp]) -> bool {
        self.request_recalc
            .unwrap_or_else(|| applied.iter().any(EditOp::may_affect_values))
    }
}

/// What a session applied: the output bytes, the ops it actually performed
/// (drives the no-phantom/no-missing manifest guarantee), and any warnings.
#[derive(Debug, Clone)]
pub struct AppliedEdit {
    pub bytes: Vec<u8>,
    pub applied_ops: Vec<EditOp>,
    pub warnings: Vec<EditWarning>,
}

/// The seam behind which the external session binaries live. In production:
/// openpyxl for [`EditSession::apply_edits`] and LibreOffice headless for
/// [`EditSession::recalc`], both inside a foreign-tier microVM. In CI: a
/// fixture implementation, so the full gate passes without either binary.
pub trait EditSession {
    /// Stage 2: apply the plan to a copy and return the edited bytes.
    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit>;

    /// Stage 3: refresh cached formula values in the edited bytes. Must
    /// preserve unknown parts; the corruption gate re-checks regardless.
    fn recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>>;

    /// Whether this session image can recalc (LibreOffice present).
    fn supports_recalc(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Validation (stage 4)
// ---------------------------------------------------------------------------

/// One corruption-gate check result. Serializes into receipts/viewer payloads;
/// the `&'static str` check name means it does not round-trip back through
/// `Deserialize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationCheck {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

/// The corruption-gate report. `ok` is the conjunction of all checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationReport {
    pub ok: bool,
    pub checks: Vec<ValidationCheck>,
}

impl ValidationReport {
    fn single_failure(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            checks: vec![ValidationCheck {
                name,
                passed: false,
                detail: detail.into(),
            }],
        }
    }
}

/// Runs the corruption + passthrough gate over the parsed input/output
/// packages. Never trusts the session's self-report: it re-derives the part
/// diff from the actual output bytes.
fn validate(before: &OpcPackage, after: &OpcPackage, format: OfficeFormat) -> ValidationReport {
    let mut checks = Vec::new();

    let content_types_present = after.contains(opc::CONTENT_TYPES_PART);
    checks.push(ValidationCheck {
        name: "content_types_present",
        passed: content_types_present,
        detail: if content_types_present {
            "output retains [Content_Types].xml".to_owned()
        } else {
            "output is missing [Content_Types].xml".to_owned()
        },
    });

    let spine_present = after.contains(format.spine_part());
    checks.push(ValidationCheck {
        name: "spine_present",
        passed: spine_present,
        detail: if spine_present {
            format!("output retains the {} spine part", format.spine_part())
        } else {
            format!("output is missing the {} spine part", format.spine_part())
        },
    });

    let referential = referential_integrity_violations(after);
    let referential_ok = referential.is_empty();
    checks.push(ValidationCheck {
        name: "referential_integrity",
        passed: referential_ok,
        detail: if referential_ok {
            "every relationship target and content-type override resolves to a part".to_owned()
        } else {
            format!("dangling references: {}", referential.join(", "))
        },
    });

    let passthrough = passthrough_violations(before, after);
    let passthrough_ok = passthrough.is_empty();
    checks.push(ValidationCheck {
        name: "passthrough_unknown_parts",
        passed: passthrough_ok,
        detail: if passthrough_ok {
            "all unknown parts survived byte-for-byte".to_owned()
        } else {
            format!(
                "unknown parts were altered or dropped: {}",
                passthrough.join(", ")
            )
        },
    });

    let ok = checks.iter().all(|c| c.passed);
    ValidationReport { ok, checks }
}

/// Names of unknown parts that were dropped, altered, or newly injected — any
/// of which violates the passthrough law.
fn passthrough_violations(before: &OpcPackage, after: &OpcPackage) -> Vec<String> {
    let mut violations = Vec::new();
    for part in before.parts() {
        if opc::classify(&part.name) != PartClass::Unknown {
            continue;
        }
        match after.part(&part.name) {
            Some(bytes) if bytes == part.data.as_slice() => {}
            Some(_) => violations.push(format!("{} (altered)", part.name)),
            None => violations.push(format!("{} (dropped)", part.name)),
        }
    }
    for part in after.parts() {
        if opc::classify(&part.name) == PartClass::Unknown && !before.contains(&part.name) {
            violations.push(format!("{} (injected)", part.name));
        }
    }
    violations
}

/// Output-package references that no longer resolve to a part: a `.rels`
/// relationship Target or a `[Content_Types].xml` Override PartName whose part
/// was dropped. Office rejects such a package outright, so a dangling reference
/// is corruption even when the dropped part itself was editable.
fn referential_integrity_violations(after: &OpcPackage) -> Vec<String> {
    let mut violations = Vec::new();
    for part in after.parts() {
        if !part.name.ends_with(".rels") {
            continue;
        }
        let Some(base) = rels_base_dir(&part.name) else {
            continue;
        };
        let xml = String::from_utf8_lossy(&part.data);
        for (target, mode) in relationship_targets(&xml) {
            // External targets name a URI, not a package part.
            if mode.as_deref() == Some("External") {
                continue;
            }
            match resolve_part_path(&base, &target) {
                Some(resolved) if after.contains(&resolved) => {}
                Some(resolved) => {
                    violations.push(format!("{} -> missing part {resolved}", part.name));
                }
                None => {
                    violations.push(format!("{} -> unresolvable target {target}", part.name));
                }
            }
        }
    }
    if let Some(content_types) = after.part(opc::CONTENT_TYPES_PART) {
        let xml = String::from_utf8_lossy(content_types);
        for part_name in scan_tag_attr(&xml, "<Override", "PartName") {
            let resolved = part_name.strip_prefix('/').unwrap_or(&part_name);
            if !after.contains(resolved) {
                violations.push(format!(
                    "[Content_Types].xml override -> missing part {resolved}"
                ));
            }
        }
    }
    violations
}

/// The directory a `.rels` part's targets resolve against: for
/// `<dir>/_rels/<name>.rels` that is `<dir>/`, and for the package-root
/// `_rels/.rels` it is the empty string.
fn rels_base_dir(rels_name: &str) -> Option<String> {
    let idx = rels_name.rfind("_rels/")?;
    Some(rels_name[..idx].to_owned())
}

/// Resolves an OPC relationship Target against a base directory, collapsing
/// `.`/`..` segments. Returns `None` when `..` escapes the package root.
fn resolve_part_path(base_dir: &str, target: &str) -> Option<String> {
    let combined = target
        .strip_prefix('/')
        .map_or_else(|| format!("{base_dir}{target}"), str::to_owned);
    let mut segments: Vec<&str> = Vec::new();
    for segment in combined.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            other => segments.push(other),
        }
    }
    Some(segments.join("/"))
}

/// Extracts `(Target, TargetMode?)` from every `<Relationship>` in a `.rels`
/// part.
fn relationship_targets(xml: &str) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(pos) = rest.find("<Relationship") {
        let after_tag = &rest[pos + "<Relationship".len()..];
        let tag_end = after_tag.find('>').unwrap_or(after_tag.len());
        let body = &after_tag[..tag_end];
        if let Some(target) = attr_value(body, "Target=\"") {
            out.push((target, attr_value(body, "TargetMode=\"")));
        }
        rest = &after_tag[tag_end..];
    }
    out
}

fn diff_parts(before: &OpcPackage, after: &OpcPackage) -> BTreeSet<String> {
    let mut touched = BTreeSet::new();
    for part in after.parts() {
        match before.part(&part.name) {
            Some(bytes) if bytes == part.data.as_slice() => {}
            _ => {
                touched.insert(part.name.clone());
            }
        }
    }
    for part in before.parts() {
        if !after.contains(&part.name) {
            touched.insert(part.name.clone());
        }
    }
    touched
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

/// Whether a recalc stage ran, and why not when it did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecalcStatus {
    NotNeeded,
    Performed,
    /// Edited bytes could not be reparsed before recalc; the gate will reject.
    Skipped,
}

/// The retained-output proposal: the new bytes plus everything a settlement
/// (ARTL-4) or viewer (ARTL-5) needs, committing nothing.
#[derive(Debug, Clone)]
pub struct EditProposal {
    pub run_ref: String,
    pub format: OfficeFormat,
    pub new_bytes: Vec<u8>,
    pub manifest: EditManifest,
    pub inspection: StructureSummary,
    pub validation: ValidationReport,
    pub recalc: RecalcStatus,
    /// The artifact version these bytes were produced FROM, when the proposal
    /// was run against a blob artifact ([`crate::Vault::propose_blob_artifact_edit`]).
    /// `None` for a raw [`run_edit_roundtrip`] with no artifact binding. ARTL-4
    /// settle records it as the receipt's before-version ref.
    pub base_version: Option<u64>,
    /// Content hash (blake3) of the base bytes the edit started from. ARTL-4
    /// settle refuses a stale proposal by requiring this to still equal the
    /// artifact head's content hash — an intervening edit changes the head hash,
    /// so committing these bytes would clobber it and replay a stale manifest.
    pub base_content_hash: [u8; 32],
}

impl EditProposal {
    /// The provenance ARTL-4 appends when it settles this proposal into a new
    /// blob version.
    #[must_use]
    pub fn agent_run_provenance(&self) -> BlobVersionProvenance {
        BlobVersionProvenance::AgentRun {
            run_ref: self.run_ref.clone(),
        }
    }
}

/// The pipeline result: a settle-ready proposal, or a rejection whose report
/// says which corruption check failed. A rejection never carries proposal
/// bytes forward.
#[derive(Debug, Clone)]
pub enum EditOutcome {
    Proposed(EditProposal),
    Rejected {
        inspection: StructureSummary,
        report: ValidationReport,
    },
}

/// Runs the full four-stage edit round-trip against a copy of `input_bytes`.
///
/// The input bytes are never mutated. On success the returned
/// [`EditProposal`] is a retained output — nothing is written to any store.
pub fn run_edit_roundtrip<S: EditSession>(
    session: &S,
    input_bytes: &[u8],
    format: OfficeFormat,
    plan: &EditPlan,
    run_ref: &str,
) -> Result<EditOutcome> {
    if run_ref.trim().is_empty() {
        return Err(Error::EditRoundtripFailed("run_ref must be non-empty"));
    }

    // The op vocabulary and inspection are spreadsheet-specific, and `classify`
    // marks `word/` and `ppt/` parts Supported — so the passthrough gate would
    // not protect a docx/pptx from a mangling session and the fidelity law
    // would be vacuous. Until format-appropriate pipelines exist, accept only
    // xlsx/xlsm; a docx/pptx artifact is an unsupported-media-type refusal.
    if !matches!(format, OfficeFormat::Xlsx) {
        return Err(Error::InvalidEditManifest(
            "edit round-trip supports only xlsx/xlsm; docx and pptx are not yet supported",
        ));
    }

    // Reject a malformed plan before it can reach a session: cells, ranges, and
    // axis positions are 1-based, but the unchecked constructors let 0 through.
    validate_ops(&plan.ops)?;

    // Stage 0: decompose the input. A bad input is a hard error (the caller
    // handed us a broken blob), distinct from a session producing bad output.
    let before = opc::read(input_bytes)?;
    let doc_before = OfficeDoc::new(format, input_bytes.to_vec(), before.clone());

    // Stage 1: inspect-first.
    let inspection = inspect(&before, format);
    let (mutation_mode, mut warnings) = mutation_mode_for(&inspection);

    // Minimal-mutation mode preserves pivot/chart/macro parts byte-for-byte,
    // and those parts index into the grid by absolute address. A structural op
    // would shift that grid and leave the preserved parts stale, so refuse it
    // here rather than emit a silently-wrong file; cell-level ops stay allowed.
    if mutation_mode == MutationMode::Minimal && plan.ops.iter().any(EditOp::is_structural) {
        return Err(Error::InvalidEditManifest(
            "minimal-mutation mode refuses structural ops: preserved pivot/chart/macro parts would go stale against the shifted grid",
        ));
    }

    // Stage 2: targeted edit through the seam.
    let applied = session.apply_edits(&doc_before, plan)?;
    let mut current = applied.bytes;
    warnings.extend(applied.warnings);

    // Stage 3: recalc when inputs changed. Fail closed if the edit may change
    // formula values but this session image cannot recalc: retaining stale
    // cached formula values in the output is silent data corruption, so refuse
    // and let the caller route to a recalc-capable session rather than propose.
    let recalc = if plan.needs_recalc(&applied.applied_ops) {
        if !session.supports_recalc() {
            return Err(Error::EditRoundtripFailed(
                "edit may change formula values but the session cannot recalc; route to a recalc-capable session",
            ));
        }
        match opc::read(&current) {
            Ok(package) => {
                let edited = OfficeDoc::new(format, current.clone(), package);
                current = session.recalc(&edited)?;
                RecalcStatus::Performed
            }
            Err(_) => RecalcStatus::Skipped,
        }
    } else {
        RecalcStatus::NotNeeded
    };

    // Stage 4: corruption + passthrough gate over the actual output bytes.
    let after = match opc::read(&current) {
        Ok(package) => package,
        Err(_) => {
            let report = ValidationReport::single_failure(
                "well_formed_opc",
                "edit output is not a readable OPC package",
            );
            return Ok(EditOutcome::Rejected { inspection, report });
        }
    };

    let manifest = EditManifest {
        schema_version: EDIT_MANIFEST_SCHEMA_VERSION,
        format,
        ops: applied.applied_ops,
        touched_parts: diff_parts(&before, &after),
        mutation_mode,
        warnings,
    };

    let report = validate(&before, &after, format);
    if !report.ok {
        return Ok(EditOutcome::Rejected { inspection, report });
    }

    Ok(EditOutcome::Proposed(EditProposal {
        run_ref: run_ref.to_owned(),
        format,
        new_bytes: current,
        manifest,
        inspection,
        validation: report,
        recalc,
        // The raw round-trip has no artifact/version context; the base is the
        // input bytes it edited. `propose_blob_artifact_edit` fills base_version.
        base_version: None,
        base_content_hash: *blake3::hash(input_bytes).as_bytes(),
    }))
}

impl crate::Vault {
    /// Runs the ARTL-3 edit round-trip against the current head bytes of a
    /// blob artifact, returning a retained-output proposal.
    ///
    /// This commits nothing: the version append (with
    /// [`BlobVersionProvenance::AgentRun`]) and the receipt are ARTL-4's
    /// settlement, driven from the returned [`EditProposal`].
    pub fn propose_blob_artifact_edit<S: EditSession>(
        &self,
        artifact_id: &EntityId,
        session: &S,
        plan: &EditPlan,
        run_ref: &str,
    ) -> Result<EditOutcome> {
        let head = self
            .blob_artifact_head(artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let bytes = self
            .read_blob_artifact_version(artifact_id, head.version)?
            .ok_or(Error::EntityNotFound)?;
        let body = self
            .get_blob_artifact(artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let format = OfficeFormat::from_media_type(&body.media_type)?;
        let mut outcome = run_edit_roundtrip(session, &bytes, format, plan, run_ref)?;
        // Bind the proposal to the head it was produced from, so ARTL-4 settle
        // can refuse it if an intervening edit has moved the head since.
        if let EditOutcome::Proposed(proposal) = &mut outcome {
            proposal.base_version = Some(head.version);
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests;
