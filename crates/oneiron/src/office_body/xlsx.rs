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
//! list. `office.tables` maps a sheet key to its tables, and `office.lines`
//! to its rows and columns with their own size or format, as JSON, as the
//! row and column edits leave them. Root `cells` maps each sheet key to a map from
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
    XlsxFormat, XlsxLines, XlsxLock, XlsxSheetPlan, XlsxSheetVisibility, XlsxStyle, XlsxTable,
    XlsxValue, a1, calculated_fill, check_cell, check_conditional, check_format, check_name,
    check_sheet_name, drop_tables, parse_a1, retarget_sheets, shift_axis_formula,
    shift_conditional_range, shift_lines,
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
    child_map, decode_axis, decode_cell, decode_lines, decode_name, encode_areas, encode_axes,
    encode_cell, encode_lines, encode_name, encode_tables, name_key, parse_lock, read_styles_len,
    string, writable_name, write_cell,
};

const OFFICE: &str = "office";
const CELLS: &str = "cells";
const NAMES: &str = "names";
const FORMATS: &str = "formats";
const CONDITIONAL: &str = "conditional";
/// The longest id of a cell format the body composes.
const MAX_FORMAT_ID: usize = 64;
pub(super) const SCHEMA: u32 = 2;

#[doc(hidden)]
pub use oneiron_records::office_body::xlsx::{
    BodyCell, BodyConditionalFormat, BodyFormat, BodyName, BodySheet, XlsxBody,
};

#[doc(hidden)]
pub use oneiron_verb_wire::office_body::xlsx::XlsxBodyOp;

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
