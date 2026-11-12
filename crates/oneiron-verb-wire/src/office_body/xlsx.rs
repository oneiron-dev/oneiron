//! Moved from `crates/oneiron/src/office_body/xlsx.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use loro::Container;
use loro::LoroDoc;
use loro::LoroMap;
use loro::LoroMapValue;
use loro::LoroValue;
use loro::ValueOrContainer;
use oneiron_docedit::xlsx_body::XlsxConditionalFormat;
use oneiron_docedit::xlsx_body::XlsxFormat;
use oneiron_docedit::xlsx_body::XlsxSheetVisibility;
use oneiron_docedit::xlsx_body::XlsxValue;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;

/// One typed operation on an XLSX body. A cell is an A1 address (`B12`,
/// `$B$12`); a formula may carry its leading `=`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum XlsxBodyOp {
    /// Write a constant; the cell's formula, if any, goes.
    SetValue {
        sheet: String,
        cell: String,
        value: XlsxValue,
    },
    /// Write a formula; its value is computed at preview and export.
    SetFormula {
        sheet: String,
        cell: String,
        formula: String,
    },
    /// Apply one of the workbook's cell formats, or none; a composed format
    /// the cell had goes.
    SetStyle {
        sheet: String,
        cell: String,
        style: Option<u32>,
    },
    /// Compose a cell format under `id` (1 to 64 letters, digits, `_`, `-`
    /// or `.`): one of the workbook's with its font, fill, border or number
    /// format changed. A format is immutable: composing an id again with
    /// another format refuses, so a changed look takes a new id.
    DefineFormat {
        id: String,
        format: XlsxFormat,
    },
    /// Apply a format the body composed; the cell's imported format goes.
    SetFormat {
        sheet: String,
        cell: String,
        format: String,
    },
    /// Add or replace conditional format `id` (1 to 64 letters, digits, `_`,
    /// `-` or `.`) on a worksheet: the cells of its range its rule matches
    /// take its look. Its range and formulas follow row and column edits.
    SetConditionalFormat {
        sheet: String,
        id: String,
        format: XlsxConditionalFormat,
    },
    /// Delete a conditional format the body added.
    DeleteConditionalFormat {
        sheet: String,
        id: String,
    },
    /// Empty a cell's content; its format stays.
    Clear {
        sheet: String,
        cell: String,
    },
    /// Add or replace a defined name, local to `sheet` or the workbook's.
    SetName {
        name: String,
        sheet: Option<String>,
        formula: String,
        hidden: bool,
    },
    DeleteName {
        name: String,
        sheet: Option<String>,
    },
    /// Add an empty worksheet at `at` in the workbook's order (0 is first),
    /// or last.
    AddSheet {
        sheet: String,
        at: Option<u32>,
    },
    /// Rename a worksheet; every formula and defined name that names it
    /// follows. Text in a string literal stays.
    RenameSheet {
        sheet: String,
        name: String,
    },
    /// Move a worksheet to `at` in the workbook's order (0 is first).
    MoveSheet {
        sheet: String,
        at: u32,
    },
    /// Delete a worksheet with its cells and its own defined names; formulas
    /// that named it read `#REF!`. A workbook keeps one worksheet, and one
    /// visible sheet: deleting the last visible one shows the first hidden
    /// one, and the edit names it.
    DeleteSheet {
        sheet: String,
    },
    /// Show or hide a worksheet's tab, as Excel's visible, hidden and very
    /// hidden. Excel keeps one sheet visible: hiding the last visible one
    /// shows another (the first hidden, then the first very hidden), or adds
    /// an empty worksheet when there is none, and the edit names it.
    SetSheetVisibility {
        sheet: String,
        visibility: XlsxSheetVisibility,
    },
    /// Insert `count` empty rows before row `at` (1-based). The rows below
    /// move down, and every formula, defined name and read-only range that
    /// reaches them follows.
    InsertRows {
        sheet: String,
        at: u32,
        count: u32,
    },
    /// Delete `count` rows from row `at` (1-based). A reference to a deleted
    /// cell reads `#REF!`; a range that loses some of its rows shrinks.
    DeleteRows {
        sheet: String,
        at: u32,
        count: u32,
    },
    /// Insert `count` empty columns before column `at` (1-based: C is 3).
    InsertColumns {
        sheet: String,
        at: u32,
        count: u32,
    },
    /// Delete `count` columns from column `at` (1-based: C is 3).
    DeleteColumns {
        sheet: String,
        at: u32,
        count: u32,
    },
}
