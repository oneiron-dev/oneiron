//! XLSX admission, projection changes and three-way diffs.
//! Entry: `changes`.
//! Definitions live here; office_body::xlsx keeps the old bindings.

use super::*;

/// Refuse operations read at `base` that write a cell or name `head` has
/// changed since: one of the two writes would be silently lost. Once rows or
/// columns moved, every address read at `base` may name another cell.
pub(in crate::office_body) fn admit_at(
    base: &LoroDoc,
    head: &LoroDoc,
    ops: &[XlsxBodyOp],
) -> Result<()> {
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
            | XlsxBodyOp::SetFormat { sheet, cell, .. }
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
            XlsxBodyOp::SetConditionalFormat { sheet, id, .. }
            | XlsxBodyOp::DeleteConditionalFormat { sheet, id } => {
                let find = |body: &XlsxBody| {
                    body.sheets
                        .iter()
                        .find(|held| held.name == *sheet)
                        .and_then(|held| held.conditional.get(id))
                        .cloned()
                };
                find(&base) != find(&head)
            }
            // A format is immutable, so only another one under this id since
            // the base is lost.
            XlsxBodyOp::DefineFormat { id, format } => {
                base.formats.get(id) != head.formats.get(id) && head.formats.get(id) != Some(format)
            }
            XlsxBodyOp::AddSheet { .. }
            | XlsxBodyOp::RenameSheet { .. }
            | XlsxBodyOp::MoveSheet { .. }
            | XlsxBodyOp::DeleteSheet { .. }
            | XlsxBodyOp::SetSheetVisibility { .. }
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

/// The changes that turn the imported `base` into `current`: the sheet layout
/// when a sheet was added, renamed, moved or deleted, the row and column
/// edits in order, the composed formats the changed cells use, then each cell
/// whose content or format differs and each defined name, against `base`
/// moved by the same edits. A cell's composed format is named by the
/// workbook's format count plus its place among those formats.
pub(in crate::office_body) fn changes(
    base: &XlsxBody,
    current: &XlsxBody,
) -> Result<Vec<XlsxChange>> {
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
                    visibility: sheet.visibility,
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
    let imported = u32::try_from(current.styles.len()).map_err(|_| invalid("XLSX body styles"))?;
    let mut used: Vec<&str> = Vec::new();
    let mut cells = Vec::new();
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
                Some(cell) => {
                    let style = match cell.format.as_deref() {
                        Some(id) => {
                            let at =
                                used.iter().position(|held| *held == id).unwrap_or_else(|| {
                                    used.push(id);
                                    used.len() - 1
                                });
                            Some(imported + at as u32)
                        }
                        None => cell.style,
                    };
                    (cell.value.clone(), cell.formula.clone(), style)
                }
                None => (XlsxValue::Blank, None, None),
            };
            cells.push(XlsxChange::Cell {
                sheet: after.name.clone(),
                col: key.1,
                row: key.0,
                value,
                formula,
                style,
            });
        }
    }
    if !used.is_empty() {
        changes.push(XlsxChange::Formats {
            formats: used
                .iter()
                .map(|id| {
                    current
                        .formats
                        .get(*id)
                        .cloned()
                        .ok_or_else(|| invalid("a cell names a format the body does not have"))
                })
                .collect::<Result<_>>()?,
        });
    }
    changes.extend(cells);
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
    changes.extend(conditional_changes(current));
    Ok(changes)
}

/// `base` as `current`'s structural edits leave it, in the order the export
/// applies them: each base sheet's fate by its key (kept, renamed or
/// deleted) first, then every row and column edit in `entries` under its
/// sheet's final name. A sheet added since reuses no base sheet's edits,
/// even under a name a base sheet had. What differs from `current` after
/// that is cell and name writes.
pub(super) fn moved(
    base: &XlsxBody,
    current: &XlsxBody,
    entries: &[(String, XlsxAxisEdit)],
) -> Result<XlsxBody> {
    let mut moved = base.clone();
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
        let order: Vec<String> = base.sheets.iter().map(|sheet| sheet.name.clone()).collect();
        let gone = gone_tables(base, |sheet| {
            !current.sheets.iter().any(|held| held.key == sheet.key)
        });
        retarget(
            &mut moved,
            &order,
            &|name: &str| {
                fates
                    .get(&name.to_lowercase())
                    .cloned()
                    .unwrap_or(SheetFate::Keep)
            },
            &gone,
        );
    }
    moved.sheets.retain_mut(|sheet| {
        match current.sheets.iter().find(|held| held.key == sheet.key) {
            Some(held) => {
                sheet.name.clone_from(&held.name);
                true
            }
            None => false,
        }
    });
    // An edit to a sheet the body later deleted leaves with the sheet.
    for (key, edit) in entries {
        if let Some(sheet) = current.sheets.iter().find(|sheet| sheet.key == *key) {
            // The live body checked each edit as it made it.
            axis(&mut moved, key, &sheet.name, edit, false)?;
        }
    }
    Ok(moved)
}

/// A fork's proposal against the live body. Units are `key!A1` cells (a
/// sheet's key is its imported name), `name:<key>` names, `format:<id>`
/// composed formats, the `sheets` layout and the `axes` row and column log.
/// A unit both sides set differently is a conflict: last-writer-wins would
/// drop one side's write silently. So is a cell or name one side wrote in a
/// sheet the other side deleted. When one side moved rows or columns and
/// the other did not, the other side's writes move by the same edits first
/// (FIX 3036): a unit conflicts where both sides end up writing it, named by
/// its address once both land, and a cell the edits delete conflicts by its
/// written address. When both sides moved rows or columns differently,
/// every cell or name one side wrote conflicts, since its address may now
/// name another cell.
pub(in crate::office_body) fn diff(
    base: &XlsxBody,
    current: &XlsxBody,
    proposal: &XlsxBody,
    frontiers: (Vec<u8>, Vec<u8>, Vec<u8>),
) -> OfficeBodyDiff {
    let theirs = side(base, current);
    let ours = side(base, proposal);
    let shifted_conflicts = one_moved(base, current, proposal)
        .and_then(|(mover, entries, writer)| moved_conflicts(base, mover, entries, writer).ok());
    let translated = shifted_conflicts.is_some();
    let mut conflicts = shifted_conflicts.unwrap_or_else(|| both_set(&ours, &theirs));
    let gone = |body: &XlsxBody| -> BTreeSet<String> {
        base.sheets
            .iter()
            .filter(|sheet| !body.sheets.iter().any(|held| held.key == sheet.key))
            .map(|sheet| sheet.key.clone())
            .collect()
    };
    for (written, deleted) in [(&ours, gone(current)), (&theirs, gone(proposal))] {
        for unit in written.keys() {
            let scope = scope_of(
                unit.strip_prefix("name:")
                    .or_else(|| unit.strip_prefix("conditional:"))
                    .unwrap_or(unit),
            );
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
    if !translated && our_axes != their_axes {
        for (moved, written) in [(&ours, &theirs), (&theirs, &ours)] {
            if !moved.contains_key("axes") {
                continue;
            }
            // A composed format names no cell.
            for unit in written.keys().filter(|unit| !unit.starts_with("format:")) {
                if !conflicts.iter().any(|held| held.block == *unit) {
                    conflicts.push(BodyConflict {
                        block: unit.clone(),
                        kind: ConflictKind::BothSet,
                    });
                }
            }
        }
    }
    let list = |changes: Units<'_>| {
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

/// One side's changed units, each with how it changed and its end state.
type Units<'a> = BTreeMap<String, (ChangeKind, State<'a>)>;

/// The units both sides changed to different end states.
fn both_set(ours: &Units<'_>, theirs: &Units<'_>) -> Vec<BodyConflict> {
    let mut conflicts = Vec::new();
    for (unit, (kind, state)) in ours {
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
    conflicts
}

/// When exactly one of `a` and `b` moved rows or columns since `base`, and
/// kept its sheets as `base` laid them out: that side, its row and column
/// edits since `base`, and the other side.
fn one_moved<'a>(
    base: &XlsxBody,
    a: &'a XlsxBody,
    b: &'a XlsxBody,
) -> Option<(&'a XlsxBody, &'a [(String, XlsxAxisEdit)], &'a XlsxBody)> {
    let entries = |side: &'a XlsxBody| side.axes.strip_prefix(base.axes.as_slice());
    let (mover, moves, writer) = match (entries(a)?, entries(b)?) {
        (moves, []) if !moves.is_empty() => (a, moves, b),
        ([], moves) if !moves.is_empty() => (b, moves, a),
        _ => return None,
    };
    // A side that renamed a sheet too moved its formulas under the new name.
    (layout(mover) == layout(base)).then_some((mover, moves, writer))
}

/// `body` with `entries`, another side's row and column edits, applied to
/// each of its sheets by key; a sheet `body` does not hold skips them.
fn shifted(body: &XlsxBody, entries: &[(String, XlsxAxisEdit)]) -> Result<XlsxBody> {
    let mut out = body.clone();
    for (key, edit) in entries {
        let Some(name) = out
            .sheets
            .iter()
            .find(|sheet| sheet.key == *key)
            .map(|sheet| sheet.name.clone())
        else {
            continue;
        };
        axis(&mut out, key, &name, edit, false)?;
    }
    Ok(out)
}

/// The conflicts of `writer`'s writes with `mover`'s, which moved rows or
/// columns by `entries` since `base`: both read once the edits moved
/// `writer`'s writes, plus each cell `writer` wrote that the edits delete.
fn moved_conflicts(
    base: &XlsxBody,
    mover: &XlsxBody,
    entries: &[(String, XlsxAxisEdit)],
    writer: &XlsxBody,
) -> Result<Vec<BodyConflict>> {
    let (moved_base, moved_writer) = (shifted(base, entries)?, shifted(writer, entries)?);
    let mut conflicts = both_set(&side(&moved_base, &moved_writer), &side(&moved_base, mover));
    for unit in side(base, writer).into_keys() {
        if ["name:", "format:", "conditional:"]
            .iter()
            .any(|prefix| unit.starts_with(prefix))
        {
            continue;
        }
        let Some((key, (col, row))) = unit
            .rsplit_once('!')
            .and_then(|(key, address)| Some((key, parse_a1(address)?)))
        else {
            continue;
        };
        let kept = entries
            .iter()
            .filter(|(sheet, _)| sheet == key)
            .try_fold((col, row), |at, (_, edit)| edit.cell(at));
        if kept.is_none() {
            conflicts.push(BodyConflict {
                block: unit,
                kind: ConflictKind::DeleteEdit,
            });
        }
    }
    Ok(conflicts)
}

/// The body a fork's landing leaves when one side moved rows or columns and
/// the other did not (FIX 3036): `merged`, the two documents merged, with
/// the moving side's cells, read-only ranges, tables, names and log, and the
/// other side's cell and name writes moved by the same edits. `None` when no
/// side's writes move, or the merge already reads so.
pub(in crate::office_body) fn landed(
    base: &XlsxBody,
    current: &XlsxBody,
    proposal: &XlsxBody,
    merged: &XlsxBody,
) -> Result<Option<XlsxBody>> {
    let Some((mover, entries, writer)) = one_moved(base, current, proposal) else {
        return Ok(None);
    };
    let (base, writer) = (shifted(base, entries)?, shifted(writer, entries)?);
    let mut out = merged.clone();
    out.axes.clone_from(&mover.axes);
    let (empty, no_rules) = (BTreeMap::new(), BTreeMap::new());
    for sheet in &mut out.sheets {
        let after = writer.sheets.iter().find(|held| held.key == sheet.key);
        let Some(held) = mover.sheets.iter().find(|held| held.key == sheet.key) else {
            // A sheet only the writer has holds its cells, formulas moved.
            if let Some(after) = after {
                sheet.cells.clone_from(&after.cells);
                sheet.conditional.clone_from(&after.conditional);
            }
            continue;
        };
        sheet.cells.clone_from(&held.cells);
        sheet.locked.clone_from(&held.locked);
        sheet.tables.clone_from(&held.tables);
        sheet.conditional.clone_from(&held.conditional);
        sheet.rows.clone_from(&held.rows);
        sheet.columns.clone_from(&held.columns);
        let Some(after) = after else {
            continue;
        };
        let held_base = base.sheets.iter().find(|held| held.key == sheet.key);
        let ruled = held_base.map_or(&no_rules, |held| &held.conditional);
        let ids: BTreeSet<&String> = ruled.keys().chain(after.conditional.keys()).collect();
        for id in ids {
            match after.conditional.get(id) {
                new if new == ruled.get(id) => {}
                Some(format) => {
                    sheet.conditional.insert(id.clone(), format.clone());
                }
                None => {
                    sheet.conditional.remove(id);
                }
            }
        }
        let before = held_base.map_or(&empty, |held| &held.cells);
        let addresses: BTreeSet<(u32, u32)> =
            before.keys().chain(after.cells.keys()).copied().collect();
        for at in addresses {
            let (old, new) = (before.get(&at), after.cells.get(&at));
            if same_cell(old, new) {
                continue;
            }
            match new {
                Some(cell) => sheet.cells.insert(at, cell.clone()),
                None => sheet.cells.remove(&at),
            };
        }
    }
    let mut names = mover.names.clone();
    let keys: BTreeSet<&String> = base.names.keys().chain(writer.names.keys()).collect();
    for key in keys {
        let (old, new) = (base.names.get(key), writer.names.get(key));
        if same_name(old, new) {
            continue;
        }
        match new {
            Some(name) => names.insert(key.clone(), name.clone()),
            None => names.remove(key),
        };
    }
    // A name that reads as the merge left it keeps that read.
    out.names = names
        .into_iter()
        .map(|(key, name)| match merged.names.get(&key) {
            Some(held) if same_name(Some(held), Some(&name)) => (key, held.clone()),
            _ => (key, name),
        })
        .collect();
    Ok((out != *merged).then_some(out))
}

/// Write `after` over the document's current state.
pub(in crate::office_body) fn write_body(doc: &LoroDoc, after: &XlsxBody) -> Result<()> {
    let before = read(doc)?;
    super::axis::write_back(doc, &before, after)
}

/// One unit's end state on a side, for comparing the sides.
#[derive(Debug, PartialEq)]
pub(super) enum State<'a> {
    Cell(Option<&'a BodyCell>),
    Name(Option<&'a BodyName>),
    Sheets(Vec<(&'a str, &'a str, XlsxSheetVisibility)>),
    Axes(&'a [(String, XlsxAxisEdit)]),
    Format(&'a XlsxFormat),
    Conditional(Option<&'a XlsxConditionalFormat>),
}

pub(super) fn side<'a>(base: &XlsxBody, other: &'a XlsxBody) -> Units<'a> {
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
    let no_rules = BTreeMap::new();
    for after in &other.sheets {
        let before = base
            .sheets
            .iter()
            .find(|held| held.key == after.key)
            .map_or(&no_rules, |held| &held.conditional);
        let ids: BTreeSet<&String> = before.keys().chain(after.conditional.keys()).collect();
        for id in ids {
            let (old, new) = (before.get(id), after.conditional.get(id));
            let kind = match (old, new) {
                (old, new) if old == new => continue,
                (None, _) => ChangeKind::Added,
                (_, None) => ChangeKind::Deleted,
                _ => ChangeKind::Text,
            };
            changes.insert(
                format!("conditional:{}!{id}", after.key),
                (kind, State::Conditional(new)),
            );
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
    for (id, format) in &other.formats {
        if base.formats.get(id) != Some(format) {
            changes.insert(
                format!("format:{id}"),
                (ChangeKind::Added, State::Format(format)),
            );
        }
    }
    changes
}
