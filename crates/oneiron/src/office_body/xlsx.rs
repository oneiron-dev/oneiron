//! The XLSX body inside its Loro document, schema 1 (ARCH-0075: "XLSX is a map
//! keyed by sheet and address").
//!
//! Root `office` holds the kind, schema and date system, and what the import
//! fixes: the worksheet names in workbook order, each sheet's read-only ranges
//! and the workbook's cell formats. Root `cells` maps each sheet to a map from
//! A1 address to one cell value: its content (`t` type, `v` value, `f`
//! formula), its format `s` and its import lock. A cell is one value, so
//! concurrent writes to it resolve last-writer-wins and a three-way read names
//! them. Clearing a cell keeps its entry. Root `names` maps `sheet!name` (lower
//! case; an empty sheet for a workbook name) to a defined name.

use super::fork::{BlockChange, BodyConflict, ChangeKind, ConflictKind, OfficeBodyDiff};
use super::invalid;
use crate::error::Result;
use loro::{Container, LoroDoc, LoroMap, LoroMapValue, LoroValue, ValueOrContainer};
use oneiron_docedit::xlsx_body::{
    XlsxArea, XlsxBook, XlsxChange, XlsxLock, XlsxStyle, XlsxValue, a1, check_cell, check_name,
    parse_a1,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};

const OFFICE: &str = "office";
const CELLS: &str = "cells";
const NAMES: &str = "names";
pub(super) const SCHEMA: u32 = 1;
/// The most stored cells a live body holds.
const MAX_CELLS: usize = 200_000;

/// A typed read of the body at one frontier.
#[derive(Debug, Clone, PartialEq)]
pub struct XlsxBody {
    pub date1904: bool,
    pub sheets: Vec<BodySheet>,
    /// Defined names by key: `sheet!name` in lower case, the sheet empty for a
    /// workbook name.
    pub names: BTreeMap<String, BodyName>,
    /// The workbook's cell formats, by index.
    pub styles: Vec<XlsxStyle>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BodySheet {
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
    let names: Vec<LoroValue> = book
        .sheets
        .iter()
        .map(|sheet| sheet.name.as_str().into())
        .collect();
    office.insert("sheets", names).map_err(loro)?;
    let locked: HashMap<String, LoroValue> = book
        .sheets
        .iter()
        .map(|sheet| {
            let areas: Vec<LoroValue> = sheet
                .locked
                .iter()
                .map(|area| {
                    LoroValue::from(vec![
                        LoroValue::from(area.reference()),
                        LoroValue::from(lock_token(area.lock)),
                    ])
                })
                .collect();
            (sheet.name.clone(), areas.into())
        })
        .collect();
    office.insert("locked", locked).map_err(loro)?;
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
    let sheet_names = list("sheets")?
        .iter()
        .map(|name| match name {
            LoroValue::String(name) => Ok(name.to_string()),
            _ => Err(invalid("XLSX body sheet name")),
        })
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
    let mut sheets = Vec::with_capacity(sheet_names.len());
    for name in sheet_names {
        let grid = child_map(&grids, &name).ok_or_else(|| invalid("XLSX body sheet"))?;
        let LoroValue::Map(entries) = grid.get_value() else {
            return Err(invalid("XLSX body sheet"));
        };
        let mut cells = BTreeMap::new();
        for (address, value) in entries.iter() {
            let (col, row) = parse_a1(address).ok_or_else(|| invalid("XLSX body cell address"))?;
            cells.insert((row, col), decode_cell(address, value)?);
        }
        let areas = match locked.get(&name) {
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
            name,
            cells,
            locked: areas,
        });
    }
    let LoroValue::Map(entries) = doc.get_map(NAMES).get_value() else {
        return Err(invalid("XLSX body names"));
    };
    let mut names = BTreeMap::new();
    for (key, value) in entries.iter() {
        let name = decode_name(value)?;
        if *key != name_key(&name.name, name.sheet.as_deref()) {
            return Err(invalid("XLSX body name key"));
        }
        names.insert(key.clone(), name);
    }
    Ok(XlsxBody {
        date1904: matches!(meta.get("date1904"), Some(LoroValue::Bool(true))),
        sheets,
        names,
        styles,
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
            if let Some(sheet) = sheet {
                child_map(&doc.get_map(CELLS), sheet)
                    .ok_or_else(|| invalid("no such worksheet in the body"))?;
            }
            let names = doc.get_map(NAMES);
            let key = name_key(name, sheet.as_deref());
            writable_name(&names, &key)?;
            let body = BodyName {
                name: name.clone(),
                sheet: sheet.clone(),
                formula: formula.to_owned(),
                hidden: *hidden,
                locked: None,
            };
            names.insert(&key, encode_name(&body)).map_err(loro)
        }
        XlsxBodyOp::DeleteName { name, sheet } => {
            let names = doc.get_map(NAMES);
            let key = name_key(name, sheet.as_deref());
            if !writable_name(&names, &key)? {
                return Err(invalid("no such defined name in the body"));
            }
            names.delete(&key).map_err(loro)
        }
    }
}

/// Refuse operations read at `base` that write a cell or name `head` has
/// changed since: one of the two writes would be silently lost.
pub(super) fn admit_at(base: &LoroDoc, head: &LoroDoc, ops: &[XlsxBodyOp]) -> Result<()> {
    let (base, head) = (read(base)?, read(head)?);
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
                let key = name_key(name, sheet.as_deref());
                base.names.get(&key) != head.names.get(&key)
            }
        };
        if moved {
            return Err(invalid(
                "a cell or name changed since the base; read it again",
            ));
        }
    }
    Ok(())
}

/// The changes that turn the imported `base` into `current`: each cell whose
/// content or format differs, then each defined name.
pub(super) fn changes(base: &XlsxBody, current: &XlsxBody) -> Result<Vec<XlsxChange>> {
    if base.sheets.len() != current.sheets.len() {
        return Err(invalid("the body's sheets changed"));
    }
    let mut changes = Vec::new();
    for (before, after) in base.sheets.iter().zip(&current.sheets) {
        if before.name != after.name {
            return Err(invalid("the body's sheets changed"));
        }
        let addresses: BTreeSet<(u32, u32)> = before
            .cells
            .keys()
            .chain(after.cells.keys())
            .copied()
            .collect();
        for key in addresses {
            let (old, new) = (before.cells.get(&key), after.cells.get(&key));
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
    let keys: BTreeSet<&String> = base.names.keys().chain(current.names.keys()).collect();
    for key in keys {
        let (old, new) = (base.names.get(key), current.names.get(key));
        if old == new {
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
                sheet: name.sheet.clone(),
            },
            (None, None) => continue,
        });
    }
    Ok(changes)
}

/// A fork's proposal against the live body. Units are `Sheet!A1` cells and
/// `name:<key>` names. A cell or name both sides set differently is a
/// conflict: last-writer-wins would drop one side's write silently.
pub(super) fn diff(
    base: &XlsxBody,
    current: &XlsxBody,
    proposal: &XlsxBody,
    frontiers: (Vec<u8>, Vec<u8>),
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
    let list = |changes: BTreeMap<String, (ChangeKind, State<'_>)>| {
        changes
            .into_iter()
            .map(|(block, (kind, _))| BlockChange { block, kind })
            .collect()
    };
    OfficeBodyDiff {
        base: frontiers.0,
        head: frontiers.1,
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
}

fn side<'a>(base: &XlsxBody, other: &'a XlsxBody) -> BTreeMap<String, (ChangeKind, State<'a>)> {
    let mut changes = BTreeMap::new();
    for (before, after) in base.sheets.iter().zip(&other.sheets) {
        let addresses: BTreeSet<(u32, u32)> = before
            .cells
            .keys()
            .chain(after.cells.keys())
            .copied()
            .collect();
        for key in addresses {
            let (old, new) = (before.cells.get(&key), after.cells.get(&key));
            if same_cell(old, new) {
                continue;
            }
            let kind = if old.is_none() {
                ChangeKind::Added
            } else {
                ChangeKind::Cells
            };
            let unit = format!("{}!{}", after.name, a1(key.1, key.0));
            changes.insert(unit, (kind, State::Cell(new)));
        }
    }
    let keys: BTreeSet<&String> = base.names.keys().chain(other.names.keys()).collect();
    for key in keys {
        let (old, new) = (base.names.get(key), other.names.get(key));
        let kind = match (old, new) {
            (old, new) if old == new => continue,
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
    let grid = child_map(&doc.get_map(CELLS), sheet)
        .ok_or_else(|| invalid("no such worksheet in the body"))?;
    let office = doc.get_map(OFFICE);
    let locked = match office.get("locked") {
        Some(ValueOrContainer::Value(LoroValue::Map(locked))) => locked,
        _ => return Err(invalid("XLSX body locks")),
    };
    if let Some(LoroValue::List(areas)) = locked.get(sheet) {
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
