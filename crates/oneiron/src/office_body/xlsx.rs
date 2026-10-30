//! Live XLSX body model and module seam.
//! Entry: `XlsxBody`.
//! read, apply, axis, diff, sheets and wire own the forwarded functions.
//!
//! The XLSX body inside its Loro document, schema 2 (ARCH-0075: "XLSX is a map
//! keyed by sheet and address").
//!
//! Root `office` holds the kind, schema and date system, the worksheets in
//! workbook order as `[key, name]` pairs, each sheet's read-only ranges by key
//! and the workbook's cell formats. A sheet's key is its imported name, or one
//! minted when the body adds it, so renaming or moving a sheet changes only the
//! list. `office.tables` maps a sheet key to its tables, as JSON, as the row
//! and column edits leave them. Root `cells` maps each sheet key to a map from
//! A1 address to one cell
//! value: its content (`t` type, `v` value, `f` formula), its format `s` and
//! its import lock. A cell is one value, so concurrent writes to it resolve
//! last-writer-wins and a three-way read names them. Clearing a cell keeps its
//! entry; a deleted sheet's cells stay under its key, which is never reused.
//! Root `names` maps `key!name` (lower case; an empty key for a workbook name)
//! to a defined name. Root `formats` maps the id of a cell format the body
//! composed to its JSON, one immutable value; a cell names one as `fmt` in
//! place of its imported format `s`.
//!
//! `office.axes` logs the body's row and column inserts and deletes in order,
//! each `[key, "row"|"col", at, count, delete]`. An address names a cell as the
//! log leaves its sheet, so an export replays the log on the imported package
//! first, then writes only the cells and names that differ from the import
//! moved by the same log. Root `conditional` maps `key!id` to a conditional
//! format the body added to the sheet keyed `key` (FIX 3468).

mod apply;
mod axis;
mod conditional;
mod diff;
mod read;
mod sheets;
mod wire;

use super::fork::{BlockChange, BodyConflict, ChangeKind, ConflictKind, OfficeBodyDiff};
use super::invalid;
use crate::error::Result;
use loro::{Container, LoroDoc, LoroMap, LoroMapValue, LoroValue, ValueOrContainer};
use oneiron_docedit::xlsx_body::{
    SheetFate, XlsxArea, XlsxAxis, XlsxAxisEdit, XlsxBook, XlsxChange, XlsxConditionalFormat,
    XlsxFormat, XlsxLock, XlsxSheetPlan, XlsxSheetVisibility, XlsxStyle, XlsxTable, XlsxValue, a1,
    calculated_fill, check_cell, check_conditional, check_format, check_name, check_sheet_name,
    drop_tables, parse_a1, retarget_sheets, shift_axis_formula, shift_conditional_range,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub(super) use apply::apply;
use axis::{axis, gone_tables, retarget, retarget_body, shift};
use conditional::{
    conditional_changes, delete_conditional, read_conditional, retarget_conditional,
    set_conditional, shift_conditional, write_conditional,
};
pub(super) use diff::{admit_at, changes, diff, landed, write_body};
pub(super) use read::{import, read};
use sheets::{
    decode_sheet, free_name, keep_one_visible, new_sheet, set_sheet_list, set_sheet_states,
    sheet_at, sheet_key, sheet_list, sheet_names, sheet_states,
};
use wire::{
    child_map, decode_axis, decode_cell, decode_name, encode_areas, encode_axes, encode_cell,
    encode_name, encode_tables, name_key, parse_lock, read_styles_len, string, writable_name,
    write_cell,
};

const OFFICE: &str = "office";
const CELLS: &str = "cells";
const NAMES: &str = "names";
const FORMATS: &str = "formats";
const CONDITIONAL: &str = "conditional";
/// The longest id of a cell format the body composes.
const MAX_FORMAT_ID: usize = 64;
pub(super) const SCHEMA: u32 = 2;

/// A typed read of the body at one frontier.
#[derive(Debug, Clone, PartialEq)]
pub struct XlsxBody {
    pub date1904: bool,
    pub sheets: Vec<BodySheet>,
    /// Defined names by key: the sheet's key and the name in lower case,
    /// `key!name`, the key empty for a workbook name.
    pub names: BTreeMap<String, BodyName>,
    /// The workbook's cell formats, by index.
    pub styles: Vec<XlsxStyle>,
    /// The row and column inserts and deletes since import, in order, by
    /// sheet key.
    pub axes: Vec<(String, XlsxAxisEdit)>,
    /// The cell formats the body composed, by id; each is immutable.
    pub formats: BTreeMap<String, XlsxFormat>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BodySheet {
    /// The sheet's key in the body: its imported name, or one minted when the
    /// body added it. A rename keeps it.
    pub key: String,
    pub name: String,
    /// `(row, col)` to cell, in row-major order.
    pub cells: BTreeMap<(u32, u32), BodyCell>,
    /// Ranges no operation writes.
    pub locked: Vec<XlsxArea>,
    pub tables: Vec<XlsxTable>,
    pub visibility: XlsxSheetVisibility,
    /// The conditional formats the body added, by id (FIX 3468).
    pub conditional: BTreeMap<String, XlsxConditionalFormat>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BodyCell {
    pub address: String,
    /// A formula cell's value is its last computed result: the import's cache,
    /// blank once the formula is rewritten. A preview or export recomputes it.
    pub value: XlsxValue,
    pub formula: Option<String>,
    pub style: Option<u32>,
    /// A cell format the body composed, by id, in place of `style`.
    pub format: Option<String>,
    pub locked: Option<XlsxLock>,
}

/// A cell format the body composed, by its id.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BodyFormat {
    pub id: String,
    pub format: XlsxFormat,
}

/// A conditional format the body added to a sheet, by its id.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BodyConditionalFormat {
    pub id: String,
    pub format: XlsxConditionalFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BodyName {
    pub name: String,
    pub sheet: Option<String>,
    pub formula: String,
    pub hidden: bool,
    pub locked: Option<XlsxLock>,
}

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

/// The body's worksheets in order, by key, name and visibility.
fn layout(body: &XlsxBody) -> Vec<(&str, &str, XlsxSheetVisibility)> {
    body.sheets
        .iter()
        .map(|sheet| (sheet.key.as_str(), sheet.name.as_str(), sheet.visibility))
        .collect()
}

/// A defined name's sheet key, from its body key; empty for a workbook name.
fn scope_of(key: &str) -> &str {
    key.rsplit_once('!').map_or("", |(scope, _)| scope)
}

/// Whether two reads of one name key hold the same name; the sheet it is
/// local to may have been renamed in between.
fn same_name(old: Option<&BodyName>, new: Option<&BodyName>) -> bool {
    match (old, new) {
        (Some(old), Some(new)) => {
            old.name == new.name && old.formula == new.formula && old.hidden == new.hidden
        }
        (old, new) => old.is_none() && new.is_none(),
    }
}

/// Whether two reads of one address hold the same cell; a missing cell is a
/// blank one without a format.
fn same_cell(old: Option<&BodyCell>, new: Option<&BodyCell>) -> bool {
    let empty = |cell: Option<&BodyCell>| {
        cell.is_none_or(|cell| {
            cell.value == XlsxValue::Blank
                && cell.formula.is_none()
                && cell.style.is_none()
                && cell.format.is_none()
        })
    };
    match (old, new) {
        (Some(old), Some(new)) => {
            old.value == new.value
                && old.formula == new.formula
                && old.style == new.style
                && old.format == new.format
        }
        _ => empty(old) && empty(new),
    }
}

fn loro(_: loro::LoroError) -> crate::error::Error {
    invalid("office body document operation")
}
