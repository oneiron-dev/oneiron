//! The XLSX body inside its Loro document, schema 2 (ARCH-0075: "XLSX is a map
//! keyed by sheet and address").
//!
//! Root `office` holds the kind, schema and date system, the worksheets in
//! workbook order as `[key, name]` pairs, each sheet's read-only ranges by key
//! and the workbook's cell formats. A sheet's key is its imported name, or one
//! minted when the body adds it, so renaming or moving a sheet changes only the
//! list. Root `cells` maps each sheet key to a map from A1 address to one cell
//! value: its content (`t` type, `v` value, `f` formula), its format `s` and
//! its import lock. A cell is one value, so concurrent writes to it resolve
//! last-writer-wins and a three-way read names them. Clearing a cell keeps its
//! entry; a deleted sheet's cells stay under its key, which is never reused.
//! Root `names` maps `key!name` (lower case; an empty key for a workbook name)
//! to a defined name.
//!
//! `office.axes` logs the body's row and column inserts and deletes in order,
//! each `[key, "row"|"col", at, count, delete]`. An address names a cell as the
//! log leaves its sheet, so an export replays the log on the imported package
//! first, then writes only the cells and names that differ from the import
//! moved by the same log.

use super::fork::{BlockChange, BodyConflict, ChangeKind, ConflictKind, OfficeBodyDiff};
use super::invalid;
use crate::error::Result;
use loro::{Container, LoroDoc, LoroMap, LoroMapValue, LoroValue, ValueOrContainer};
use oneiron_docedit::xlsx_body::{
    SheetFate, XlsxArea, XlsxAxis, XlsxAxisEdit, XlsxBook, XlsxChange, XlsxLock, XlsxSheetPlan,
    XlsxStyle, XlsxValue, a1, check_cell, check_name, check_sheet_name, parse_a1, retarget_sheets,
    shift_axis,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};

const OFFICE: &str = "office";
const CELLS: &str = "cells";
const NAMES: &str = "names";
pub(super) const SCHEMA: u32 = 2;
/// The most stored cells a live body holds.
const MAX_CELLS: usize = 200_000;

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
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BodyCell {
    pub address: String,
    /// A formula cell's value is its last computed result: the import's cache,
    /// blank once the formula is rewritten. A preview or export recomputes it.
    pub value: XlsxValue,
    pub formula: Option<String>,
    pub style: Option<u32>,
    pub locked: Option<XlsxLock>,
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
    /// Apply one of the workbook's cell formats, or none.
    SetStyle {
        sheet: String,
        cell: String,
        style: Option<u32>,
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
    /// that named it read `#REF!`. A workbook keeps one worksheet.
    DeleteSheet {
        sheet: String,
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

/// Write the imported workbook into a fresh document.
pub(super) fn import(doc: &LoroDoc, book: &XlsxBook) -> Result<()> {
    if book
        .sheets
        .iter()
        .map(|sheet| sheet.cells.len())
        .sum::<usize>()
        > MAX_CELLS
    {
        return Err(invalid("the workbook holds more cells than a live body"));
    }
    let office = doc.get_map(OFFICE);
    office.insert("kind", "xlsx").map_err(loro)?;
    office.insert("schema", i64::from(SCHEMA)).map_err(loro)?;
    office.insert("date1904", book.date1904).map_err(loro)?;
    let sheets: Vec<(String, String)> = book
        .sheets
        .iter()
        .map(|sheet| (sheet.name.clone(), sheet.name.clone()))
        .collect();
    set_sheet_list(doc, &sheets)?;
    let locked: HashMap<String, LoroValue> = book
        .sheets
        .iter()
        .map(|sheet| (sheet.name.clone(), encode_areas(&sheet.locked)))
        .collect();
    office.insert("locked", locked).map_err(loro)?;
    office
        .insert("axes", Vec::<LoroValue>::new())
        .map_err(loro)?;
    let styles: Vec<LoroValue> = book
        .styles
        .iter()
        .map(|style| {
            LoroValue::from(vec![
                LoroValue::from(i64::from(style.num_fmt)),
                style
                    .format
                    .as_deref()
                    .map_or(LoroValue::Null, LoroValue::from),
            ])
        })
        .collect();
    office.insert("styles", styles).map_err(loro)?;
    let cells = doc.get_map(CELLS);
    for sheet in &book.sheets {
        if cells.get(&sheet.name).is_some() {
            return Err(invalid("duplicate imported sheet name"));
        }
        let grid = cells
            .insert_container(&sheet.name, LoroMap::new())
            .map_err(loro)?;
        for cell in &sheet.cells {
            let body = BodyCell {
                address: a1(cell.col, cell.row),
                value: cell.value.clone(),
                formula: cell.formula.clone(),
                style: cell.style,
                locked: cell.locked,
            };
            grid.insert(&body.address, encode_cell(&body))
                .map_err(loro)?;
        }
    }
    let names = doc.get_map(NAMES);
    for name in &book.names {
        let key = name_key(&name.name, name.sheet.as_deref());
        if names.get(&key).is_some() {
            return Err(invalid("duplicate imported defined name"));
        }
        let body = BodyName {
            name: name.name.clone(),
            sheet: name.sheet.clone(),
            formula: name.formula.clone(),
            hidden: name.hidden,
            locked: name.locked,
        };
        names.insert(&key, encode_name(&body)).map_err(loro)?;
    }
    Ok(())
}

/// The body's typed state; a malformed document fails closed.
pub(super) fn read(doc: &LoroDoc) -> Result<XlsxBody> {
    let office = doc.get_map(OFFICE);
    let LoroValue::Map(meta) = office.get_value() else {
        return Err(invalid("not a schema-1 XLSX body"));
    };
    if string(&meta, "kind").as_deref() != Some("xlsx")
        || meta.get("schema") != Some(&LoroValue::I64(i64::from(SCHEMA)))
    {
        return Err(invalid("not a schema-1 XLSX body"));
    }
    let list = |key: &str| match meta.get(key) {
        Some(LoroValue::List(list)) => Ok(list.clone()),
        _ => Err(invalid("XLSX body metadata")),
    };
    let sheet_list = list("sheets")?
        .iter()
        .map(decode_sheet)
        .collect::<Result<Vec<_>>>()?;
    let Some(LoroValue::Map(locked)) = meta.get("locked") else {
        return Err(invalid("XLSX body locks"));
    };
    let styles = list("styles")?
        .iter()
        .map(|style| match style {
            LoroValue::List(pair) => match pair.as_slice() {
                [LoroValue::I64(num_fmt), format] => Ok(XlsxStyle {
                    num_fmt: u32::try_from(*num_fmt).map_err(|_| invalid("XLSX body style"))?,
                    format: match format {
                        LoroValue::String(code) => Some(code.to_string()),
                        _ => None,
                    },
                }),
                _ => Err(invalid("XLSX body style")),
            },
            _ => Err(invalid("XLSX body style")),
        })
        .collect::<Result<Vec<_>>>()?;
    let grids = doc.get_map(CELLS);
    let mut sheets = Vec::with_capacity(sheet_list.len());
    for (key, name) in sheet_list {
        let grid = child_map(&grids, &key).ok_or_else(|| invalid("XLSX body sheet"))?;
        let LoroValue::Map(entries) = grid.get_value() else {
            return Err(invalid("XLSX body sheet"));
        };
        let mut cells = BTreeMap::new();
        for (address, value) in entries.iter() {
            let (col, row) = parse_a1(address).ok_or_else(|| invalid("XLSX body cell address"))?;
            cells.insert((row, col), decode_cell(address, value)?);
        }
        let areas = match locked.get(&key) {
            None => Vec::new(),
            Some(LoroValue::List(areas)) => areas
                .iter()
                .map(|area| match area {
                    LoroValue::List(pair) => match pair.as_slice() {
                        [LoroValue::String(reference), LoroValue::String(lock)] => {
                            XlsxArea::parse(reference, parse_lock(lock)?)
                                .ok_or_else(|| invalid("XLSX body locked range"))
                        }
                        _ => Err(invalid("XLSX body locked range")),
                    },
                    _ => Err(invalid("XLSX body locked range")),
                })
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(invalid("XLSX body locks")),
        };
        sheets.push(BodySheet {
            key,
            name,
            cells,
            locked: areas,
        });
    }
    let axes = match meta.get("axes") {
        None => Vec::new(),
        Some(LoroValue::List(list)) => list.iter().map(decode_axis).collect::<Result<Vec<_>>>()?,
        Some(_) => return Err(invalid("XLSX body row and column edits")),
    };
    let LoroValue::Map(entries) = doc.get_map(NAMES).get_value() else {
        return Err(invalid("XLSX body names"));
    };
    let mut names = BTreeMap::new();
    for (key, value) in entries.iter() {
        let mut name = decode_name(value)?;
        if *key != name_key(&name.name, name.sheet.as_deref()) {
            return Err(invalid("XLSX body name key"));
        }
        // A local name reads its sheet's name; one whose sheet a concurrent
        // edit deleted is gone with it.
        if let Some(scope) = &name.sheet {
            let Some(sheet) = sheets.iter().find(|sheet| sheet.key == *scope) else {
                continue;
            };
            name.sheet = Some(sheet.name.clone());
        }
        names.insert(key.clone(), name);
    }
    Ok(XlsxBody {
        date1904: matches!(meta.get("date1904"), Some(LoroValue::Bool(true))),
        sheets,
        names,
        styles,
        axes,
    })
}

/// Apply one operation.
pub(super) fn apply(doc: &LoroDoc, op: &XlsxBodyOp) -> Result<()> {
    match op {
        XlsxBodyOp::SetValue { sheet, cell, value } => {
            check_cell(value, None).map_err(|_| invalid("the value is not one a cell holds"))?;
            write_cell(doc, sheet, cell, |held| BodyCell {
                value: value.clone(),
                formula: None,
                ..held
            })
        }
        XlsxBodyOp::SetFormula {
            sheet,
            cell,
            formula,
        } => {
            let formula = formula.strip_prefix('=').unwrap_or(formula);
            check_cell(&XlsxValue::Blank, Some(formula))
                .map_err(|_| invalid("a formula is 1 to 8,192 characters"))?;
            write_cell(doc, sheet, cell, |held| BodyCell {
                value: XlsxValue::Blank,
                formula: Some(formula.to_owned()),
                ..held
            })
        }
        XlsxBodyOp::SetStyle { sheet, cell, style } => {
            if let Some(style) = style {
                let count = read_styles_len(doc)?;
                if *style as usize >= count {
                    return Err(invalid("a cell format the workbook does not have"));
                }
            }
            write_cell(doc, sheet, cell, |held| BodyCell {
                style: *style,
                ..held
            })
        }
        XlsxBodyOp::Clear { sheet, cell } => write_cell(doc, sheet, cell, |held| BodyCell {
            value: XlsxValue::Blank,
            formula: None,
            ..held
        }),
        XlsxBodyOp::SetName {
            name,
            sheet,
            formula,
            hidden,
        } => {
            check_name(name).map_err(|_| invalid("not a valid defined name"))?;
            let formula = formula.strip_prefix('=').unwrap_or(formula);
            check_cell(&XlsxValue::Blank, Some(formula))
                .map_err(|_| invalid("a name's formula is 1 to 8,192 characters"))?;
            let scope = sheet
                .as_deref()
                .map(|sheet| sheet_key(doc, sheet))
                .transpose()?;
            let names = doc.get_map(NAMES);
            let key = name_key(name, scope.as_deref());
            writable_name(&names, &key)?;
            let body = BodyName {
                name: name.clone(),
                sheet: scope,
                formula: formula.to_owned(),
                hidden: *hidden,
                locked: None,
            };
            names.insert(&key, encode_name(&body)).map_err(loro)
        }
        XlsxBodyOp::DeleteName { name, sheet } => {
            let scope = sheet
                .as_deref()
                .map(|sheet| sheet_key(doc, sheet))
                .transpose()?;
            let names = doc.get_map(NAMES);
            let key = name_key(name, scope.as_deref());
            if !writable_name(&names, &key)? {
                return Err(invalid("no such defined name in the body"));
            }
            names.delete(&key).map_err(loro)
        }
        XlsxBodyOp::AddSheet { sheet, at } => {
            check_sheet_name(sheet).map_err(|_| invalid("not a valid worksheet name"))?;
            let mut list = sheet_list(doc)?;
            free_name(&list, sheet, None)?;
            let at = at.map_or(list.len(), |at| at as usize);
            if at > list.len() {
                return Err(invalid("a sheet position past the last sheet"));
            }
            let cells = doc.get_map(CELLS);
            let mut key = format!("+{sheet}");
            let mut n = 1;
            while cells.get(&key).is_some() {
                n += 1;
                key = format!("+{sheet}#{n}");
            }
            cells.insert_container(&key, LoroMap::new()).map_err(loro)?;
            list.insert(at, (key, sheet.clone()));
            set_sheet_list(doc, &list)
        }
        XlsxBodyOp::RenameSheet { sheet, name } => {
            check_sheet_name(name).map_err(|_| invalid("not a valid worksheet name"))?;
            let mut list = sheet_list(doc)?;
            let at = sheet_at(&list, sheet)?;
            free_name(&list, name, Some(at))?;
            list[at].1.clone_from(name);
            set_sheet_list(doc, &list)?;
            let old = sheet.to_lowercase();
            retarget_body(doc, &|held: &str| {
                if held.to_lowercase() == old {
                    SheetFate::Rename(name.clone())
                } else {
                    SheetFate::Keep
                }
            })
        }
        XlsxBodyOp::MoveSheet { sheet, at } => {
            let mut list = sheet_list(doc)?;
            let from = sheet_at(&list, sheet)?;
            let at = *at as usize;
            if at >= list.len() {
                return Err(invalid("a sheet position past the last sheet"));
            }
            let held = list.remove(from);
            list.insert(at, held);
            set_sheet_list(doc, &list)
        }
        XlsxBodyOp::DeleteSheet { sheet } => {
            let mut list = sheet_list(doc)?;
            let at = sheet_at(&list, sheet)?;
            if list.len() == 1 {
                return Err(invalid("a workbook keeps at least one worksheet"));
            }
            let (key, _) = list.remove(at);
            set_sheet_list(doc, &list)?;
            let names = doc.get_map(NAMES);
            let LoroValue::Map(entries) = names.get_value() else {
                return Err(invalid("XLSX body names"));
            };
            for held in entries.keys() {
                if held.rsplit_once('!').is_some_and(|(scope, _)| scope == key) {
                    names.delete(held).map_err(loro)?;
                }
            }
            let old = sheet.to_lowercase();
            retarget_body(doc, &|held: &str| {
                if held.to_lowercase() == old {
                    SheetFate::Delete
                } else {
                    SheetFate::Keep
                }
            })
        }
        XlsxBodyOp::InsertRows { sheet, at, count } => shift(
            doc,
            sheet,
            XlsxAxisEdit {
                axis: XlsxAxis::Row,
                at: *at,
                count: *count,
                delete: false,
            },
        ),
        XlsxBodyOp::DeleteRows { sheet, at, count } => shift(
            doc,
            sheet,
            XlsxAxisEdit {
                axis: XlsxAxis::Row,
                at: *at,
                count: *count,
                delete: true,
            },
        ),
        XlsxBodyOp::InsertColumns { sheet, at, count } => shift(
            doc,
            sheet,
            XlsxAxisEdit {
                axis: XlsxAxis::Column,
                at: *at,
                count: *count,
                delete: false,
            },
        ),
        XlsxBodyOp::DeleteColumns { sheet, at, count } => shift(
            doc,
            sheet,
            XlsxAxisEdit {
                axis: XlsxAxis::Column,
                at: *at,
                count: *count,
                delete: true,
            },
        ),
    }
}

/// Insert or delete rows or columns in one sheet, and log the edit.
fn shift(doc: &LoroDoc, sheet: &str, edit: XlsxAxisEdit) -> Result<()> {
    if !edit.fits() {
        return Err(invalid("rows or columns off the sheet"));
    }
    let before = read(doc)?;
    let held = before
        .sheets
        .iter()
        .find(|held| held.name == sheet)
        .ok_or_else(|| invalid("no such worksheet in the body"))?;
    let (key, name) = (held.key.clone(), held.name.clone());
    let mut after = before.clone();
    axis(&mut after, &key, &name, &edit, true)?;
    after.axes.push((key, edit));
    write_back(doc, &before, &after)
}

/// Insert or delete rows or columns in the sheet keyed `key`, which formulas
/// name `name`: its cells and read-only ranges move or go, and every formula
/// and defined name that reaches it follows. A deleted reference reads
/// `#REF!` and a range that loses part of itself shrinks; a formula that
/// moves loses its cached value. With `check`, refuse what an export could
/// not write: a shared formula the body cannot write out, a read-only range
/// the edit would split or cut, a cell pushed off the sheet.
fn axis(
    body: &mut XlsxBody,
    key: &str,
    name: &str,
    edit: &XlsxAxisEdit,
    check: bool,
) -> Result<()> {
    if check
        && body
            .sheets
            .iter()
            .flat_map(|sheet| sheet.cells.values())
            .any(|cell| cell.locked == Some(XlsxLock::SharedFormula))
    {
        return Err(invalid(
            "the workbook holds a shared formula the body cannot write out, so rows and columns stay",
        ));
    }
    if let Some(sheet) = body.sheets.iter_mut().find(|sheet| sheet.key == key) {
        let end = edit.at + edit.count - 1;
        let mut locked = Vec::with_capacity(sheet.locked.len());
        for area in &sheet.locked {
            let (low, high) = match edit.axis {
                XlsxAxis::Row => (area.first.1, area.last.1),
                XlsxAxis::Column => (area.first.0, area.last.0),
            };
            let split = !edit.delete && low < edit.at && edit.at <= high;
            // A table's header or totals row never goes; other ranges go
            // only whole.
            let cut = edit.delete
                && low <= end
                && edit.at <= high
                && (area.lock == XlsxLock::TableRow || low < edit.at || high > end);
            if check && (split || cut) {
                return Err(invalid(
                    "the rows or columns would split or cut a read-only range",
                ));
            }
            if let Some((first, last)) = edit.area(area.first, area.last) {
                locked.push(XlsxArea {
                    first,
                    last,
                    ..*area
                });
            }
        }
        sheet.locked = locked;
        let mut cells = BTreeMap::new();
        for ((row, col), cell) in std::mem::take(&mut sheet.cells) {
            match edit.cell((col, row)) {
                Some((col, row)) => {
                    cells.insert(
                        (row, col),
                        BodyCell {
                            address: a1(col, row),
                            ..cell
                        },
                    );
                }
                None if check && !edit.delete && !same_cell(Some(&cell), None) => {
                    return Err(invalid("the insert would push a cell off the sheet"));
                }
                None => {}
            }
        }
        sheet.cells = cells;
    }
    for sheet in &mut body.sheets {
        let home = sheet.name.as_str();
        for cell in sheet.cells.values_mut() {
            if let Some(formula) = cell
                .formula
                .as_deref()
                .and_then(|formula| shift_axis(formula, Some(home), name, edit))
            {
                cell.formula = Some(formula);
                cell.value = XlsxValue::Blank;
            }
        }
    }
    for held in body.names.values_mut() {
        if let Some(formula) = shift_axis(&held.formula, None, name, edit) {
            held.formula = formula;
        }
    }
    Ok(())
}

/// Retarget every formula and defined name in the body's sheets that names a
/// renamed or deleted sheet.
fn retarget_body(doc: &LoroDoc, fate: &dyn Fn(&str) -> SheetFate) -> Result<()> {
    let before = read(doc)?;
    let mut after = before.clone();
    retarget(&mut after, fate);
    write_back(doc, &before, &after)
}

/// Retarget every formula and defined name that names a renamed or deleted
/// sheet, read-only ones too, as an export's sheet layout does. A formula
/// loses its cached value.
fn retarget(body: &mut XlsxBody, fate: &dyn Fn(&str) -> SheetFate) {
    for cell in body
        .sheets
        .iter_mut()
        .flat_map(|sheet| sheet.cells.values_mut())
    {
        if let Some(formula) = cell
            .formula
            .as_deref()
            .and_then(|formula| retarget_sheets(formula, fate))
        {
            cell.formula = Some(formula);
            cell.value = XlsxValue::Blank;
        }
    }
    for held in body.names.values_mut() {
        if let Some(formula) = retarget_sheets(&held.formula, fate) {
            held.formula = formula;
        }
    }
}

/// Write what differs between two typed reads of the document: cells,
/// read-only ranges, defined names and the row and column log.
fn write_back(doc: &LoroDoc, before: &XlsxBody, after: &XlsxBody) -> Result<()> {
    let grids = doc.get_map(CELLS);
    for sheet in &after.sheets {
        let old = before.sheets.iter().find(|held| held.key == sheet.key);
        let grid = child_map(&grids, &sheet.key).ok_or_else(|| invalid("XLSX body sheet"))?;
        for at in old.iter().flat_map(|old| old.cells.keys()) {
            if !sheet.cells.contains_key(at) {
                grid.delete(&a1(at.1, at.0)).map_err(loro)?;
            }
        }
        for (at, cell) in &sheet.cells {
            if old.and_then(|old| old.cells.get(at)) != Some(cell) {
                grid.insert(&a1(at.1, at.0), encode_cell(cell))
                    .map_err(loro)?;
            }
        }
    }
    let office = doc.get_map(OFFICE);
    let moved: Vec<&BodySheet> = after
        .sheets
        .iter()
        .filter(|sheet| {
            before
                .sheets
                .iter()
                .find(|held| held.key == sheet.key)
                .is_none_or(|held| held.locked != sheet.locked)
        })
        .collect();
    if !moved.is_empty() {
        let Some(ValueOrContainer::Value(LoroValue::Map(held))) = office.get("locked") else {
            return Err(invalid("XLSX body locks"));
        };
        let mut locked: HashMap<String, LoroValue> = held
            .iter()
            .map(|(key, areas)| (key.clone(), areas.clone()))
            .collect();
        for sheet in moved {
            locked.insert(sheet.key.clone(), encode_areas(&sheet.locked));
        }
        office.insert("locked", locked).map_err(loro)?;
    }
    let names = doc.get_map(NAMES);
    for (key, name) in &after.names {
        if before.names.get(key) != Some(name) {
            // The document holds a local name's sheet by key.
            let scope = scope_of(key);
            let stored = BodyName {
                sheet: (!scope.is_empty()).then(|| scope.to_owned()),
                ..name.clone()
            };
            names.insert(key, encode_name(&stored)).map_err(loro)?;
        }
    }
    for key in before.names.keys() {
        if !after.names.contains_key(key) {
            names.delete(key).map_err(loro)?;
        }
    }
    if before.axes != after.axes {
        office
            .insert("axes", encode_axes(&after.axes))
            .map_err(loro)?;
    }
    Ok(())
}

/// Refuse operations read at `base` that write a cell or name `head` has
/// changed since: one of the two writes would be silently lost. Once rows or
/// columns moved, every address read at `base` may name another cell.
pub(super) fn admit_at(base: &LoroDoc, head: &LoroDoc, ops: &[XlsxBodyOp]) -> Result<()> {
    let (base, head) = (read(base)?, read(head)?);
    if !ops.is_empty() && base.axes != head.axes {
        return Err(invalid(
            "rows or columns moved since the base; read it again",
        ));
    }
    for op in ops {
        let moved = match op {
            XlsxBodyOp::SetValue { sheet, cell, .. }
            | XlsxBodyOp::SetFormula { sheet, cell, .. }
            | XlsxBodyOp::SetStyle { sheet, cell, .. }
            | XlsxBodyOp::Clear { sheet, cell } => {
                let (col, row) = parse_a1(cell).ok_or_else(|| invalid("not a cell address"))?;
                let find = |body: &XlsxBody| {
                    body.sheets
                        .iter()
                        .find(|held| held.name == *sheet)
                        .and_then(|held| held.cells.get(&(row, col)))
                        .cloned()
                };
                !same_cell(find(&base).as_ref(), find(&head).as_ref())
            }
            XlsxBodyOp::SetName { name, sheet, .. } | XlsxBodyOp::DeleteName { name, sheet } => {
                let lower = name.to_lowercase();
                let find = |body: &XlsxBody| {
                    body.names
                        .values()
                        .find(|held| held.name.to_lowercase() == lower && held.sheet == *sheet)
                        .cloned()
                };
                find(&base) != find(&head)
            }
            XlsxBodyOp::AddSheet { .. }
            | XlsxBodyOp::RenameSheet { .. }
            | XlsxBodyOp::MoveSheet { .. }
            | XlsxBodyOp::DeleteSheet { .. }
            | XlsxBodyOp::InsertRows { .. }
            | XlsxBodyOp::DeleteRows { .. }
            | XlsxBodyOp::InsertColumns { .. }
            | XlsxBodyOp::DeleteColumns { .. } => layout(&base) != layout(&head),
        };
        if moved {
            return Err(invalid(
                "a cell, name or sheet changed since the base; read it again",
            ));
        }
    }
    Ok(())
}

/// The body's worksheets in order, by key and name.
fn layout(body: &XlsxBody) -> Vec<(&str, &str)> {
    body.sheets
        .iter()
        .map(|sheet| (sheet.key.as_str(), sheet.name.as_str()))
        .collect()
}

/// A defined name's sheet key, from its body key; empty for a workbook name.
fn scope_of(key: &str) -> &str {
    key.rsplit_once('!').map_or("", |(scope, _)| scope)
}

/// The changes that turn the imported `base` into `current`: the sheet layout
/// when a sheet was added, renamed, moved or deleted, the row and column
/// edits in order, then each cell whose content or format differs and each
/// defined name, against `base` moved by the same edits.
pub(super) fn changes(base: &XlsxBody, current: &XlsxBody) -> Result<Vec<XlsxChange>> {
    let entries = current
        .axes
        .strip_prefix(base.axes.as_slice())
        .ok_or_else(|| invalid("the body's row and column edits do not follow its base's"))?;
    let mut changes = Vec::new();
    if layout(base) != layout(current) {
        changes.push(XlsxChange::Sheets {
            sheets: current
                .sheets
                .iter()
                .map(|sheet| XlsxSheetPlan {
                    name: sheet.name.clone(),
                    source: base
                        .sheets
                        .iter()
                        .find(|held| held.key == sheet.key)
                        .map(|held| held.name.clone()),
                })
                .collect(),
        });
    }
    // An edit to a sheet the body later deleted leaves with the sheet.
    for (key, edit) in entries {
        if let Some(sheet) = current.sheets.iter().find(|sheet| sheet.key == *key) {
            changes.push(XlsxChange::Shift {
                sheet: sheet.name.clone(),
                edit: *edit,
            });
        }
    }
    let base = &moved(base, current, entries)?;
    let empty = BTreeMap::new();
    for after in &current.sheets {
        let before = base
            .sheets
            .iter()
            .find(|held| held.key == after.key)
            .map_or(&empty, |held| &held.cells);
        let addresses: BTreeSet<(u32, u32)> =
            before.keys().chain(after.cells.keys()).copied().collect();
        for key in addresses {
            let (old, new) = (before.get(&key), after.cells.get(&key));
            if same_cell(old, new) {
                continue;
            }
            if old.is_some_and(|cell| cell.locked.is_some()) {
                return Err(invalid("a read-only cell changed"));
            }
            let (value, formula, style) = match new {
                Some(cell) => (cell.value.clone(), cell.formula.clone(), cell.style),
                None => (XlsxValue::Blank, None, None),
            };
            changes.push(XlsxChange::Cell {
                sheet: after.name.clone(),
                col: key.1,
                row: key.0,
                value,
                formula,
                style,
            });
        }
    }
    // A name local to a deleted sheet leaves with the sheet's layout.
    let keys: BTreeSet<&String> = base
        .names
        .keys()
        .chain(current.names.keys())
        .filter(|key| {
            let scope = scope_of(key);
            scope.is_empty() || current.sheets.iter().any(|sheet| sheet.key == scope)
        })
        .collect();
    for key in keys {
        let (old, new) = (base.names.get(key), current.names.get(key));
        if same_name(old, new) {
            continue;
        }
        if old.is_some_and(|name| name.locked.is_some()) {
            return Err(invalid("a read-only name changed"));
        }
        changes.push(match (old, new) {
            (_, Some(name)) => XlsxChange::SetName {
                name: name.name.clone(),
                sheet: name.sheet.clone(),
                formula: name.formula.clone(),
                hidden: name.hidden,
            },
            (Some(name), None) => XlsxChange::DeleteName {
                name: name.name.clone(),
                sheet: current
                    .sheets
                    .iter()
                    .find(|sheet| sheet.key == scope_of(key))
                    .map(|sheet| sheet.name.clone()),
            },
            (None, None) => continue,
        });
    }
    Ok(changes)
}

/// `base` as `current`'s structural edits leave it: moved by the row and
/// column edits `entries`, each matched by the sheet's name in `base` (an
/// added sheet's in `current`), then retargeted to `current`'s sheet layout.
/// What differs from `current` after that is cell and name writes.
fn moved(
    base: &XlsxBody,
    current: &XlsxBody,
    entries: &[(String, XlsxAxisEdit)],
) -> Result<XlsxBody> {
    let mut moved = base.clone();
    for (key, edit) in entries {
        let name = base
            .sheets
            .iter()
            .chain(&current.sheets)
            .find(|sheet| sheet.key == *key)
            .map(|sheet| sheet.name.clone());
        if let Some(name) = name {
            // The live body checked each edit as it made it.
            axis(&mut moved, key, &name, edit, false)?;
        }
    }
    let fates: HashMap<String, SheetFate> = base
        .sheets
        .iter()
        .filter_map(|sheet| {
            let fate = match current.sheets.iter().find(|held| held.key == sheet.key) {
                None => SheetFate::Delete,
                Some(held) if held.name != sheet.name => SheetFate::Rename(held.name.clone()),
                Some(_) => return None,
            };
            Some((sheet.name.to_lowercase(), fate))
        })
        .collect();
    if !fates.is_empty() {
        retarget(&mut moved, &|name: &str| {
            fates
                .get(&name.to_lowercase())
                .cloned()
                .unwrap_or(SheetFate::Keep)
        });
    }
    Ok(moved)
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

/// A fork's proposal against the live body. Units are `key!A1` cells (a
/// sheet's key is its imported name), `name:<key>` names, the `sheets`
/// layout and the `axes` row and column log. A unit both sides set
/// differently is a conflict: last-writer-wins would drop one side's write
/// silently. So is a cell or name one side wrote in a sheet the other side
/// deleted, and every unit one side wrote while the other moved rows or
/// columns, since its address may now name another cell.
pub(super) fn diff(
    base: &XlsxBody,
    current: &XlsxBody,
    proposal: &XlsxBody,
    frontiers: (Vec<u8>, Vec<u8>, Vec<u8>),
) -> OfficeBodyDiff {
    let theirs = side(base, current);
    let ours = side(base, proposal);
    let mut conflicts = Vec::new();
    for (unit, (kind, state)) in &ours {
        let Some((other, other_state)) = theirs.get(unit) else {
            continue;
        };
        if state == other_state {
            continue;
        }
        conflicts.push(BodyConflict {
            block: unit.clone(),
            kind: if *kind == ChangeKind::Deleted || *other == ChangeKind::Deleted {
                ConflictKind::DeleteEdit
            } else {
                ConflictKind::BothSet
            },
        });
    }
    let gone = |body: &XlsxBody| -> BTreeSet<String> {
        base.sheets
            .iter()
            .filter(|sheet| !body.sheets.iter().any(|held| held.key == sheet.key))
            .map(|sheet| sheet.key.clone())
            .collect()
    };
    for (written, deleted) in [(&ours, gone(current)), (&theirs, gone(proposal))] {
        for unit in written.keys() {
            let scope = scope_of(unit.strip_prefix("name:").unwrap_or(unit));
            if deleted.contains(scope) && !conflicts.iter().any(|held| held.block == *unit) {
                conflicts.push(BodyConflict {
                    block: unit.clone(),
                    kind: ConflictKind::DeleteEdit,
                });
            }
        }
    }
    let (our_axes, their_axes) = (
        ours.get("axes").map(|(_, state)| state),
        theirs.get("axes").map(|(_, state)| state),
    );
    if our_axes != their_axes {
        for (moved, written) in [(&ours, &theirs), (&theirs, &ours)] {
            if !moved.contains_key("axes") {
                continue;
            }
            for unit in written.keys() {
                if !conflicts.iter().any(|held| held.block == *unit) {
                    conflicts.push(BodyConflict {
                        block: unit.clone(),
                        kind: ConflictKind::BothSet,
                    });
                }
            }
        }
    }
    let list = |changes: BTreeMap<String, (ChangeKind, State<'_>)>| {
        changes
            .into_iter()
            .map(|(block, (kind, _))| BlockChange { block, kind })
            .collect()
    };
    OfficeBodyDiff {
        base: frontiers.0,
        head: frontiers.1,
        fork_head: frontiers.2,
        proposal: list(ours),
        current: list(theirs),
        conflicts,
    }
}

/// One unit's end state on a side, for comparing the sides.
#[derive(Debug, PartialEq)]
enum State<'a> {
    Cell(Option<&'a BodyCell>),
    Name(Option<&'a BodyName>),
    Sheets(Vec<(&'a str, &'a str)>),
    Axes(&'a [(String, XlsxAxisEdit)]),
}

fn side<'a>(base: &XlsxBody, other: &'a XlsxBody) -> BTreeMap<String, (ChangeKind, State<'a>)> {
    let mut changes = BTreeMap::new();
    if layout(base) != layout(other) {
        changes.insert(
            "sheets".to_owned(),
            (ChangeKind::Moved, State::Sheets(layout(other))),
        );
    }
    if base.axes != other.axes {
        changes.insert(
            "axes".to_owned(),
            (ChangeKind::Moved, State::Axes(&other.axes)),
        );
    }
    let empty = BTreeMap::new();
    for after in &other.sheets {
        let before = base
            .sheets
            .iter()
            .find(|held| held.key == after.key)
            .map_or(&empty, |held| &held.cells);
        let addresses: BTreeSet<(u32, u32)> =
            before.keys().chain(after.cells.keys()).copied().collect();
        for key in addresses {
            let (old, new) = (before.get(&key), after.cells.get(&key));
            if same_cell(old, new) {
                continue;
            }
            let kind = if old.is_none() {
                ChangeKind::Added
            } else {
                ChangeKind::Cells
            };
            let unit = format!("{}!{}", after.key, a1(key.1, key.0));
            changes.insert(unit, (kind, State::Cell(new)));
        }
    }
    let keys: BTreeSet<&String> = base.names.keys().chain(other.names.keys()).collect();
    for key in keys {
        let (old, new) = (base.names.get(key), other.names.get(key));
        let kind = match (old, new) {
            (old, new) if same_name(old, new) => continue,
            (None, _) => ChangeKind::Added,
            (_, None) => ChangeKind::Deleted,
            _ => ChangeKind::Text,
        };
        changes.insert(format!("name:{key}"), (kind, State::Name(new)));
    }
    changes
}

/// Whether two reads of one address hold the same cell; a missing cell is a
/// blank one without a format.
fn same_cell(old: Option<&BodyCell>, new: Option<&BodyCell>) -> bool {
    let empty = |cell: Option<&BodyCell>| {
        cell.is_none_or(|cell| {
            cell.value == XlsxValue::Blank && cell.formula.is_none() && cell.style.is_none()
        })
    };
    match (old, new) {
        (Some(old), Some(new)) => {
            old.value == new.value && old.formula == new.formula && old.style == new.style
        }
        _ => empty(old) && empty(new),
    }
}

/// Write one cell from its current state (a blank one when absent). A cell
/// inside a read-only range, or locked at import, refuses.
fn write_cell(
    doc: &LoroDoc,
    sheet: &str,
    cell: &str,
    edit: impl FnOnce(BodyCell) -> BodyCell,
) -> Result<()> {
    let (col, row) = parse_a1(cell).ok_or_else(|| invalid("not a cell address"))?;
    let address = a1(col, row);
    let key = sheet_key(doc, sheet)?;
    let grid = child_map(&doc.get_map(CELLS), &key).ok_or_else(|| invalid("XLSX body sheet"))?;
    let office = doc.get_map(OFFICE);
    let locked = match office.get("locked") {
        Some(ValueOrContainer::Value(LoroValue::Map(locked))) => locked,
        _ => return Err(invalid("XLSX body locks")),
    };
    if let Some(LoroValue::List(areas)) = locked.get(&key) {
        for area in areas.iter() {
            if let LoroValue::List(pair) = area
                && let [LoroValue::String(reference), _] = pair.as_slice()
                && XlsxArea::parse(reference, XlsxLock::Unsupported)
                    .is_some_and(|area| area.contains(col, row))
            {
                return Err(invalid("the cell is read-only in the body"));
            }
        }
    }
    let held = match grid.get(&address) {
        Some(ValueOrContainer::Value(value)) => decode_cell(&address, &value)?,
        None => BodyCell {
            address: address.clone(),
            value: XlsxValue::Blank,
            formula: None,
            style: None,
            locked: None,
        },
        Some(_) => return Err(invalid("XLSX body cell")),
    };
    if held.locked.is_some() {
        return Err(invalid("the cell is read-only in the body"));
    }
    grid.insert(&address, encode_cell(&edit(held)))
        .map_err(loro)
}

/// Whether the name exists; a read-only one refuses.
fn writable_name(names: &LoroMap, key: &str) -> Result<bool> {
    match names.get(key) {
        None => Ok(false),
        Some(ValueOrContainer::Value(value)) => {
            if decode_name(&value)?.locked.is_some() {
                return Err(invalid("the name is read-only in the body"));
            }
            Ok(true)
        }
        Some(_) => Err(invalid("XLSX body name")),
    }
}

/// The body's worksheets in workbook order, as `(key, name)`.
fn sheet_list(doc: &LoroDoc) -> Result<Vec<(String, String)>> {
    match doc.get_map(OFFICE).get("sheets") {
        Some(ValueOrContainer::Value(LoroValue::List(list))) => {
            list.iter().map(decode_sheet).collect()
        }
        _ => Err(invalid("XLSX body metadata")),
    }
}

fn set_sheet_list(doc: &LoroDoc, sheets: &[(String, String)]) -> Result<()> {
    let list: Vec<LoroValue> = sheets
        .iter()
        .map(|(key, name)| {
            LoroValue::from(vec![
                LoroValue::from(key.as_str()),
                LoroValue::from(name.as_str()),
            ])
        })
        .collect();
    doc.get_map(OFFICE).insert("sheets", list).map_err(loro)
}

fn decode_sheet(value: &LoroValue) -> Result<(String, String)> {
    match value {
        LoroValue::List(pair) => match pair.as_slice() {
            [LoroValue::String(key), LoroValue::String(name)] => {
                Ok((key.to_string(), name.to_string()))
            }
            _ => Err(invalid("XLSX body sheet")),
        },
        _ => Err(invalid("XLSX body sheet")),
    }
}

fn sheet_at(sheets: &[(String, String)], name: &str) -> Result<usize> {
    sheets
        .iter()
        .position(|(_, held)| held == name)
        .ok_or_else(|| invalid("no such worksheet in the body"))
}

fn sheet_key(doc: &LoroDoc, name: &str) -> Result<String> {
    let sheets = sheet_list(doc)?;
    Ok(sheets[sheet_at(&sheets, name)?].0.clone())
}

/// Refuse a sheet name another sheet holds, in any case.
fn free_name(sheets: &[(String, String)], name: &str, except: Option<usize>) -> Result<()> {
    let lower = name.to_lowercase();
    if sheets
        .iter()
        .enumerate()
        .any(|(at, (_, held))| Some(at) != except && held.to_lowercase() == lower)
    {
        return Err(invalid("another sheet has that name"));
    }
    Ok(())
}

fn read_styles_len(doc: &LoroDoc) -> Result<usize> {
    match doc.get_map(OFFICE).get("styles") {
        Some(ValueOrContainer::Value(LoroValue::List(styles))) => Ok(styles.len()),
        _ => Err(invalid("XLSX body styles")),
    }
}

fn name_key(name: &str, sheet: Option<&str>) -> String {
    format!("{}!{}", sheet.unwrap_or_default(), name.to_lowercase())
}

fn encode_cell(cell: &BodyCell) -> LoroValue {
    let mut map: HashMap<String, LoroValue> = HashMap::new();
    let (kind, value) = match &cell.value {
        XlsxValue::Blank => ("blank", None),
        XlsxValue::Number(number) => ("n", Some(LoroValue::from(*number))),
        XlsxValue::Text(text) => ("s", Some(LoroValue::from(text.as_str()))),
        XlsxValue::Bool(flag) => ("b", Some(LoroValue::from(*flag))),
        XlsxValue::Error(error) => ("e", Some(LoroValue::from(error.as_str()))),
    };
    map.insert("t".into(), kind.into());
    if let Some(value) = value {
        map.insert("v".into(), value);
    }
    if let Some(formula) = &cell.formula {
        map.insert("f".into(), formula.as_str().into());
    }
    if let Some(style) = cell.style {
        map.insert("s".into(), i64::from(style).into());
    }
    if let Some(lock) = cell.locked {
        map.insert("lock".into(), lock_token(lock).into());
    }
    map.into()
}

fn decode_cell(address: &str, value: &LoroValue) -> Result<BodyCell> {
    let LoroValue::Map(map) = value else {
        return Err(invalid("XLSX body cell"));
    };
    let bad = || invalid("XLSX body cell");
    let value = match (string(map, "t").as_deref(), map.get("v")) {
        (Some("blank"), None) => XlsxValue::Blank,
        (Some("n"), Some(LoroValue::Double(number))) => XlsxValue::Number(*number),
        (Some("s"), Some(LoroValue::String(text))) => XlsxValue::Text(text.to_string()),
        (Some("b"), Some(LoroValue::Bool(flag))) => XlsxValue::Bool(*flag),
        (Some("e"), Some(LoroValue::String(error))) => XlsxValue::Error(error.to_string()),
        _ => return Err(bad()),
    };
    let style = match map.get("s") {
        None => None,
        Some(LoroValue::I64(style)) => Some(u32::try_from(*style).map_err(|_| bad())?),
        Some(_) => return Err(bad()),
    };
    Ok(BodyCell {
        address: address.to_owned(),
        value,
        formula: string(map, "f"),
        style,
        locked: string(map, "lock").as_deref().map(parse_lock).transpose()?,
    })
}

fn encode_areas(areas: &[XlsxArea]) -> LoroValue {
    areas
        .iter()
        .map(|area| {
            LoroValue::from(vec![
                LoroValue::from(area.reference()),
                LoroValue::from(lock_token(area.lock)),
            ])
        })
        .collect::<Vec<_>>()
        .into()
}

fn encode_axes(axes: &[(String, XlsxAxisEdit)]) -> Vec<LoroValue> {
    axes.iter()
        .map(|(key, edit)| {
            LoroValue::from(vec![
                LoroValue::from(key.as_str()),
                LoroValue::from(match edit.axis {
                    XlsxAxis::Row => "row",
                    XlsxAxis::Column => "col",
                }),
                LoroValue::from(i64::from(edit.at)),
                LoroValue::from(i64::from(edit.count)),
                LoroValue::from(edit.delete),
            ])
        })
        .collect()
}

fn decode_axis(value: &LoroValue) -> Result<(String, XlsxAxisEdit)> {
    let bad = || invalid("XLSX body row or column edit");
    let LoroValue::List(entry) = value else {
        return Err(bad());
    };
    let [
        LoroValue::String(key),
        LoroValue::String(axis),
        LoroValue::I64(at),
        LoroValue::I64(count),
        LoroValue::Bool(delete),
    ] = entry.as_slice()
    else {
        return Err(bad());
    };
    let edit = XlsxAxisEdit {
        axis: match axis.to_string().as_str() {
            "row" => XlsxAxis::Row,
            "col" => XlsxAxis::Column,
            _ => return Err(bad()),
        },
        at: u32::try_from(*at).map_err(|_| bad())?,
        count: u32::try_from(*count).map_err(|_| bad())?,
        delete: *delete,
    };
    if !edit.fits() {
        return Err(bad());
    }
    Ok((key.to_string(), edit))
}

fn encode_name(name: &BodyName) -> LoroValue {
    let mut map: HashMap<String, LoroValue> = HashMap::new();
    map.insert("name".into(), name.name.as_str().into());
    if let Some(sheet) = &name.sheet {
        map.insert("sheet".into(), sheet.as_str().into());
    }
    map.insert("formula".into(), name.formula.as_str().into());
    map.insert("hidden".into(), name.hidden.into());
    if let Some(lock) = name.locked {
        map.insert("lock".into(), lock_token(lock).into());
    }
    map.into()
}

fn decode_name(value: &LoroValue) -> Result<BodyName> {
    let LoroValue::Map(map) = value else {
        return Err(invalid("XLSX body name"));
    };
    Ok(BodyName {
        name: string(map, "name").ok_or_else(|| invalid("XLSX body name"))?,
        sheet: string(map, "sheet"),
        formula: string(map, "formula").ok_or_else(|| invalid("XLSX body name"))?,
        hidden: matches!(map.get("hidden"), Some(LoroValue::Bool(true))),
        locked: string(map, "lock").as_deref().map(parse_lock).transpose()?,
    })
}

fn lock_token(lock: XlsxLock) -> &'static str {
    match lock {
        XlsxLock::SharedFormula => "shared_formula",
        XlsxLock::ArrayFormula => "array_formula",
        XlsxLock::DataTable => "data_table",
        XlsxLock::RichValue => "rich_value",
        XlsxLock::TableRow => "table_row",
        XlsxLock::Unsupported => "unsupported",
        XlsxLock::BuiltinName => "builtin_name",
    }
}

fn parse_lock(token: &str) -> Result<XlsxLock> {
    Ok(match token {
        "shared_formula" => XlsxLock::SharedFormula,
        "array_formula" => XlsxLock::ArrayFormula,
        "data_table" => XlsxLock::DataTable,
        "rich_value" => XlsxLock::RichValue,
        "table_row" => XlsxLock::TableRow,
        "unsupported" => XlsxLock::Unsupported,
        "builtin_name" => XlsxLock::BuiltinName,
        _ => return Err(invalid("XLSX body lock")),
    })
}

fn string(map: &LoroMapValue, key: &str) -> Option<String> {
    match map.get(key) {
        Some(LoroValue::String(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn child_map(map: &LoroMap, key: &str) -> Option<LoroMap> {
    match map.get(key)? {
        ValueOrContainer::Container(Container::Map(child)) => Some(child),
        _ => None,
    }
}

fn loro(_: loro::LoroError) -> crate::error::Error {
    invalid("office body document operation")
}
