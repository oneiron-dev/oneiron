//! Live XLSX axis edits and formula retargeting.
//! Entry: `shift`.
//! Definitions live here; office_body::xlsx keeps the old bindings.

use super::*;

/// Insert or delete rows or columns in one sheet, and log the edit.
pub(super) fn shift(doc: &LoroDoc, sheet: &str, edit: XlsxAxisEdit) -> Result<()> {
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
    if !edit.delete {
        neighbour_formats(&mut after, &key, &edit);
    }
    after.axes.push((key, edit));
    write_back(doc, &before, &after)
}

/// Format inserted rows like the row above them, and inserted columns like
/// the column to their left, as Excel's insert does by default; at the
/// sheet's first row or column, like the one after them. Each formatted cell
/// of that line gives its format to the blank cells inserted beside it,
/// outside the read-only ranges. The cells are the body's writes, so an
/// export writes them as it writes any cell.
pub(super) fn neighbour_formats(body: &mut XlsxBody, key: &str, edit: &XlsxAxisEdit) {
    let Some(sheet) = body.sheets.iter_mut().find(|sheet| sheet.key == key) else {
        return;
    };
    let source = if edit.at > 1 {
        edit.at - 1
    } else {
        edit.at + edit.count
    };
    let line = |(row, col): (u32, u32)| match edit.axis {
        XlsxAxis::Row => row,
        XlsxAxis::Column => col,
    };
    let formatted: Vec<((u32, u32), Option<u32>, Option<String>)> = sheet
        .cells
        .iter()
        .filter(|(at, cell)| {
            line(**at) == source
                && cell.locked.is_none()
                && (cell.style.is_some() || cell.format.is_some())
        })
        .map(|(at, cell)| (*at, cell.style, cell.format.clone()))
        .collect();
    for ((row, col), style, format) in formatted {
        for new in edit.at..edit.at.saturating_add(edit.count) {
            let (row, col) = match edit.axis {
                XlsxAxis::Row => (new, col),
                XlsxAxis::Column => (row, new),
            };
            let address = a1(col, row);
            if parse_a1(&address).is_none()
                || sheet.locked.iter().any(|area| area.contains(col, row))
            {
                continue;
            }
            sheet.cells.entry((row, col)).or_insert_with(|| BodyCell {
                address,
                value: XlsxValue::Blank,
                formula: None,
                style,
                format: format.clone(),
                locked: None,
            });
        }
    }
}

/// Insert or delete rows or columns in the sheet keyed `key`, which formulas
/// name `name`: its cells and read-only ranges move or go, and every formula
/// and defined name that reaches it follows. A deleted reference reads
/// `#REF!` and a range that loses part of itself shrinks; a formula that
/// moves loses its cached value. Its tables move too, gaining or losing the
/// columns inserted or deleted inside them, as the export's do: a new
/// column's header cell holds its `ColumnN` name in the format of the header
/// cell to its left, and a structured reference to a deleted column reads
/// `#REF!`, an unqualified one (`[@Price]`) in a formula inside the table
/// too. Rows inserted inside a table's data area take its calculated
/// columns' formulas, each in the format of the neighbour row's writable
/// cell in its column, as the export's do. With `check`, refuse what an
/// export could not write: a shared
/// formula the body cannot write out, a read-only range the edit would split
/// or cut, a table's header or totals row or all of a table deleted, a column
/// edit inside a query or XML table, a cell pushed off the sheet.
pub(super) fn axis(
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
    // Each table that loses columns, as it was, with the names it loses.
    let mut dropped: Vec<(XlsxTable, Vec<String>)> = Vec::new();
    // Each moved table (by its index) whose calculated columns rows
    // inserted inside it take, with its first data row as the edit moves
    // it (FIX 3695).
    let mut fills: Vec<(usize, u32)> = Vec::new();
    if let Some(sheet) = body.sheets.iter_mut().find(|sheet| sheet.key == key) {
        let end = edit.at + edit.count - 1;
        let mut locked = Vec::with_capacity(sheet.locked.len());
        for area in &sheet.locked {
            let (low, high) = match edit.axis {
                XlsxAxis::Row => (area.first.1, area.last.1),
                XlsxAxis::Column => (area.first.0, area.last.0),
            };
            let table = area.lock == XlsxLock::TableRow;
            let columns = table && edit.axis == XlsxAxis::Column;
            let split = !edit.delete && low < edit.at && edit.at <= high && !columns;
            let whole = edit.at <= low && high <= end;
            // A table's header or totals row never goes, nor all of its
            // columns; other ranges go only whole.
            let cut = edit.delete
                && low <= end
                && edit.at <= high
                && if columns { whole } else { table || !whole };
            if check && cut && columns {
                return Err(invalid("the columns would delete a table"));
            }
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
        let mut tables = Vec::with_capacity(sheet.tables.len());
        // Each inserted table column's header cell: column, row and name.
        let mut headers = Vec::new();
        for table in &sheet.tables {
            let Some(shift) = table.shifted(edit) else {
                if check {
                    return Err(invalid("the rows or columns would delete a table"));
                }
                continue;
            };
            let inside = !(shift.deleted.is_empty() && shift.inserted.is_empty());
            if check && inside && !table.worksheet {
                return Err(invalid("a column edit inside a query or XML table"));
            }
            if let Some(row) = shift.table.header_row() {
                headers.extend(
                    shift
                        .inserted
                        .iter()
                        .map(|(col, name)| (*col, row, name.clone())),
                );
            }
            if !shift.deleted.is_empty() {
                dropped.push((table.clone(), shift.deleted));
            }
            if !edit.delete
                && edit.axis == XlsxAxis::Row
                && let Some(anchor) = table
                    .first
                    .1
                    .checked_add(table.header_rows)
                    .and_then(|row| edit.moved(row))
            {
                fills.push((tables.len(), anchor));
            }
            tables.push(shift.table);
        }
        sheet.tables = tables;
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
        for (col, row, title) in headers {
            let style = sheet
                .cells
                .get(&(row, edit.at - 1))
                .and_then(|cell| cell.style);
            sheet.cells.insert(
                (row, col),
                BodyCell {
                    address: a1(col, row),
                    value: XlsxValue::Text(title),
                    formula: None,
                    style,
                    format: None,
                    locked: Some(XlsxLock::TableRow),
                },
            );
        }
    }
    for sheet in &mut body.sheets {
        let BodySheet {
            name: home,
            cells,
            tables,
            ..
        } = sheet;
        let home = home.as_str();
        for (&(row, col), cell) in cells.iter_mut() {
            // An unqualified structured reference is to the table holding
            // the cell (FIX 3438).
            let own = tables
                .iter()
                .find(|table| table.contains(col, row))
                .map(|table| table.name.as_str());
            if let Some(formula) = cell.formula.as_deref().and_then(|formula| {
                shift_axis_formula(formula, Some(home), name, edit, &dropped, own)
            }) {
                cell.formula = Some(formula);
                cell.value = XlsxValue::Blank;
            }
        }
        // A table's calculated formulas follow as its part's do.
        for table in tables.iter_mut() {
            let own = table.name.clone();
            for formula in table.calculated.iter_mut().flatten() {
                if let Some(moved) = shift_axis_formula(
                    formula.as_str(),
                    Some(home),
                    name,
                    edit,
                    &dropped,
                    Some(&own),
                ) {
                    *formula = moved;
                }
            }
        }
    }
    for held in body.names.values_mut() {
        if let Some(formula) = shift_axis_formula(&held.formula, None, name, edit, &dropped, None) {
            held.formula = formula;
        }
    }
    if let Some(sheet) = body.sheets.iter_mut().find(|sheet| sheet.key == key) {
        let source = if edit.at > 1 {
            edit.at - 1
        } else {
            edit.at.saturating_add(edit.count)
        };
        for (at, anchor) in fills {
            for (col, row, formula) in calculated_fill(&sheet.tables[at], anchor, edit) {
                let like = sheet
                    .cells
                    .get(&(source, col))
                    .filter(|cell| cell.locked.is_none());
                let (style, format) =
                    like.map_or((None, None), |cell| (cell.style, cell.format.clone()));
                sheet.cells.insert(
                    (row, col),
                    BodyCell {
                        address: a1(col, row),
                        value: XlsxValue::Blank,
                        formula: Some(formula),
                        style,
                        format,
                        locked: None,
                    },
                );
            }
        }
    }
    Ok(())
}

/// Retarget every formula and defined name in the body's sheets that names a
/// renamed or deleted sheet, or a table in `gone` (lower case) that went
/// with one; `order` is the sheets' names before the change.
pub(super) fn retarget_body(
    doc: &LoroDoc,
    order: &[String],
    fate: &dyn Fn(&str) -> SheetFate,
    gone: &HashSet<String>,
) -> Result<()> {
    let before = read(doc)?;
    let mut after = before.clone();
    retarget(&mut after, order, fate, gone);
    write_back(doc, &before, &after)
}

/// The names (lower case) of the tables on the sheets `picked` names.
pub(super) fn gone_tables(body: &XlsxBody, picked: impl Fn(&BodySheet) -> bool) -> HashSet<String> {
    body.sheets
        .iter()
        .filter(|sheet| picked(sheet))
        .flat_map(|sheet| sheet.tables.iter().map(|table| table.name.to_lowercase()))
        .collect()
}

/// Retarget every formula and defined name that names a renamed or deleted
/// sheet, read-only ones too, as an export's sheet layout does; `order` is
/// the sheets' names before the change. A reference to a table in `gone`
/// (lower case), which went with its sheet, reads `#REF!`. A formula loses
/// its cached value.
pub(super) fn retarget(
    body: &mut XlsxBody,
    order: &[String],
    fate: &dyn Fn(&str) -> SheetFate,
    gone: &HashSet<String>,
) {
    let rewrite = |formula: &str| -> Option<String> {
        let moved = retarget_sheets(formula, order, fate);
        if gone.is_empty() {
            return moved;
        }
        drop_tables(moved.as_deref().unwrap_or(formula), gone).or(moved)
    };
    for cell in body
        .sheets
        .iter_mut()
        .flat_map(|sheet| sheet.cells.values_mut())
    {
        if let Some(formula) = cell.formula.as_deref().and_then(&rewrite) {
            cell.formula = Some(formula);
            cell.value = XlsxValue::Blank;
        }
    }
    // A table's calculated formulas follow as its part's do (FIX 3695).
    for formula in body
        .sheets
        .iter_mut()
        .flat_map(|sheet| sheet.tables.iter_mut())
        .flat_map(|table| table.calculated.iter_mut().flatten())
    {
        if let Some(moved) = rewrite(formula.as_str()) {
            *formula = moved;
        }
    }
    for held in body.names.values_mut() {
        if let Some(formula) = rewrite(&held.formula) {
            held.formula = formula;
        }
    }
}

/// Write what differs between two typed reads of the document: cells,
/// read-only ranges, defined names and the row and column log.
pub(super) fn write_back(doc: &LoroDoc, before: &XlsxBody, after: &XlsxBody) -> Result<()> {
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
    let retabled: Vec<&BodySheet> = after
        .sheets
        .iter()
        .filter(
            |sheet| match before.sheets.iter().find(|held| held.key == sheet.key) {
                Some(held) => held.tables != sheet.tables,
                None => !sheet.tables.is_empty(),
            },
        )
        .collect();
    if !retabled.is_empty() {
        let mut tables: HashMap<String, LoroValue> = match office.get("tables") {
            Some(ValueOrContainer::Value(LoroValue::Map(held))) => held
                .iter()
                .map(|(key, tables)| (key.clone(), tables.clone()))
                .collect(),
            _ => HashMap::new(),
        };
        for sheet in retabled {
            tables.insert(sheet.key.clone(), encode_tables(&sheet.tables)?);
        }
        office.insert("tables", tables).map_err(loro)?;
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
