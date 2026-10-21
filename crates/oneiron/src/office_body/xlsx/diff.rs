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
/// sheet the other side deleted, and every cell or name one side wrote while
/// the other moved rows or columns, since its address may now name another
/// cell.
pub(in crate::office_body) fn diff(
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
pub(super) enum State<'a> {
    Cell(Option<&'a BodyCell>),
    Name(Option<&'a BodyName>),
    Sheets(Vec<(&'a str, &'a str, XlsxSheetVisibility)>),
    Axes(&'a [(String, XlsxAxisEdit)]),
    Format(&'a XlsxFormat),
}

pub(super) fn side<'a>(
    base: &XlsxBody,
    other: &'a XlsxBody,
) -> BTreeMap<String, (ChangeKind, State<'a>)> {
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
