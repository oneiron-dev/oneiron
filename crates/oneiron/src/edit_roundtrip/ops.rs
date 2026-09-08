//! Edit operation vocabulary and anchor effects.

use super::address::column_to_letters;
use super::{Axis, CellRef, RangeRef};
use serde::{Deserialize, Serialize};

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
