//! Workbook format, cell and name projection.
//! Entry: `project_xlsx`.
//! Definitions live here; xlsx_body retains the old API and shared Book state.

use super::*;

/// Write `changes` into the imported package. Only the rows and names they
/// touch are rebuilt; every other byte of the package is kept. A change to a
/// read-only cell or name refuses. When a formula is removed, sheets are laid
/// out again or rows and columns move, the workbook's calculation chain is
/// dropped, since it would name the wrong cells; the opening application
/// rebuilds it.
pub fn project_xlsx(
    source: &[u8],
    changes: &[XlsxChange],
    limits: Limits,
    resources: &crate::resource::Resources,
) -> Result<XlsxProjection> {
    if changes.is_empty() {
        return Ok(XlsxProjection {
            bytes: source.to_vec(),
            effects: Vec::new(),
        });
    }
    let mut book = Book::open(source, limits, resources)?;
    let mut defined = changes.iter().filter_map(|change| match change {
        XlsxChange::Formats { formats } => Some(formats),
        _ => None,
    });
    let formats = defined.next();
    if defined.next().is_some() {
        return Err(refused("two lists of cell formats"));
    }
    // A cell names a composed format past the workbook's own; it takes the
    // index the stylesheet gave it.
    let remapped: Vec<XlsxChange>;
    let changes = match formats {
        Some(formats) => {
            let imported = book.styles.len();
            let indices = book.resolve_formats(formats)?;
            remapped = changes
                .iter()
                .map(|change| {
                    let mut change = change.clone();
                    if let XlsxChange::Cell {
                        style: Some(style), ..
                    } = &mut change
                        && *style as usize >= imported
                    {
                        *style = *indices
                            .get(*style as usize - imported)
                            .ok_or(refused("a cell names a format the body did not compose"))?;
                    }
                    Ok(change)
                })
                .collect::<Result<_>>()?;
            &remapped[..]
        }
        None => changes,
    };
    let mut relaid = false;
    for change in changes {
        if let XlsxChange::Sheets { sheets } = change {
            if relaid {
                return Err(refused("two sheet layouts"));
            }
            book.relayout(sheets)?;
            relaid = true;
        }
    }
    let shifts: Vec<(&str, &XlsxAxisEdit)> = changes
        .iter()
        .filter_map(|change| match change {
            XlsxChange::Shift { sheet, edit } => Some((sheet.as_str(), edit)),
            _ => None,
        })
        .collect();
    if !shifts.is_empty() {
        book.unshare_all()?;
        for (sheet, edit) in shifts {
            book.shift(sheet, edit)?;
        }
        relaid = true;
    }
    unshare_written_anchors(&mut book, changes)?;
    let mut by_sheet: BTreeMap<&str, BTreeMap<u32, BTreeMap<u32, &XlsxChange>>> = BTreeMap::new();
    let mut names = Vec::new();
    for change in changes {
        let XlsxChange::Cell {
            sheet,
            col,
            row,
            value,
            formula,
            style,
        } = change
        else {
            if !matches!(
                change,
                XlsxChange::Sheets { .. }
                    | XlsxChange::Shift { .. }
                    | XlsxChange::Formats { .. }
                    | XlsxChange::RenameColumn { .. }
            ) {
                names.push(change);
            }
            continue;
        };
        check_cell(value, formula.as_deref())?;
        if !(1..=MAX_COLUMN).contains(col) || !(1..=MAX_ROW).contains(row) {
            return Err(refused("a cell outside the sheet"));
        }
        if style.is_some_and(|style| style as usize >= book.styles.len().max(1)) {
            return Err(refused("a cell format the workbook does not have"));
        }
        if by_sheet
            .entry(sheet.as_str())
            .or_default()
            .entry(*row)
            .or_default()
            .insert(*col, change)
            .is_some()
        {
            return Err(refused("two changes write one cell"));
        }
    }
    // A column rename writes its table part and the references to the
    // column first, and admits the write of its header cell (FIX 6399).
    let mut admitted: HashSet<(&str, u32, u32)> = HashSet::new();
    for change in changes {
        let XlsxChange::RenameColumn {
            sheet,
            table,
            column,
            name,
        } = change
        else {
            continue;
        };
        let (col, row) = book.rename_column(sheet, table, column, name)?;
        let paired = by_sheet
            .get(sheet.as_str())
            .and_then(|rows| rows.get(&row))
            .and_then(|line| line.get(&col))
            .copied();
        if !matches!(
            paired,
            Some(XlsxChange::Cell { value: XlsxValue::Text(text), formula: None, .. }) if text == name
        ) {
            return Err(refused(
                "a column rename needs its header cell written with the same name",
            ));
        }
        if !admitted.insert((sheet.as_str(), col, row)) {
            return Err(refused("two renames of one column"));
        }
    }
    let mut dropped_formula = false;
    for (sheet, rows) in &by_sheet {
        let part = book
            .worksheets
            .get(*sheet)
            .ok_or(refused("no such worksheet"))?
            .clone();
        let (cells, areas, _) = book.sheet(&part)?;
        let stored: BTreeMap<(u32, u32), &XlsxCell> = cells
            .iter()
            .map(|cell| ((cell.col, cell.row), cell))
            .collect();
        // A format-only write patches the stored cell's s= alone, so a rich
        // shared string or a shared formula member keeps its markup.
        let mut restyled = BTreeSet::new();
        for (row, line) in rows {
            for (col, change) in line {
                let held = stored.get(&(*col, *row));
                // A header cell its column's rename admits (FIX 6399).
                let open = |lock: XlsxLock| {
                    lock == XlsxLock::TableRow && admitted.contains(&(*sheet, *col, *row))
                };
                if held
                    .and_then(|cell| cell.locked)
                    .is_some_and(|lock| !open(lock))
                    || areas
                        .iter()
                        .any(|area| area.contains(*col, *row) && !open(area.lock))
                {
                    return Err(refused("a change writes a read-only cell"));
                }
                let writes_formula = matches!(
                    change,
                    XlsxChange::Cell {
                        formula: Some(_),
                        ..
                    }
                );
                dropped_formula |=
                    held.is_some_and(|cell| cell.formula.is_some()) && !writes_formula;
                if format_only(change, held.copied()) {
                    restyled.insert((*col, *row));
                }
            }
        }
        let bytes = rewrite_rows(&book.package, &part, rows, &restyled)?;
        book.package.replace_xml_part(&part, bytes)?;
    }
    if !names.is_empty() {
        book.rewrite_names(&names)?;
    }
    // A layout change or a row or column edit moves the cells the chain
    // indexes.
    if (dropped_formula || relaid)
        && let Some(chain) = book
            .package
            .relationships(&book.part)?
            .into_iter()
            .find(|rel| !rel.external && rel.kind.ends_with("/calcChain"))
    {
        // The chain lists formula cells; the opening application rebuilds a
        // missing one, so it leaves with its link rather than go stale.
        book.package.unrelate(&book.part, &chain.id)?;
        if book.package.names().any(|name| name == chain.target) {
            book.package.remove_part(&chain.target)?;
        }
    }
    Ok(XlsxProjection {
        bytes: book.package.export()?,
        effects: book.effects,
    })
}

/// Whether `change` keeps `held`'s stored value and formula: a write of its
/// format alone.
pub(super) fn format_only(change: &XlsxChange, held: Option<&XlsxCell>) -> bool {
    matches!(
        (change, held),
        (XlsxChange::Cell { value, formula, .. }, Some(held))
            if held.value == *value && held.formula == *formula
    )
}

/// A content write to a shared formula's anchor first writes every member
/// of its group out as its own formula, in place, since the anchor holds
/// the group's only text; a format-only write leaves the group shared.
pub(super) fn unshare_written_anchors(book: &mut Book, changes: &[XlsxChange]) -> Result<()> {
    let mut written: BTreeMap<&str, HashMap<(u32, u32), &XlsxChange>> = BTreeMap::new();
    for change in changes {
        if let XlsxChange::Cell {
            sheet, col, row, ..
        } = change
        {
            written
                .entry(sheet.as_str())
                .or_default()
                .insert((*col, *row), change);
        }
    }
    for (sheet, cells_written) in &written {
        let Some(part) = book.worksheets.get(*sheet).cloned() else {
            continue;
        };
        let (cells, _, _) = book.sheet(&part)?;
        let stored: HashMap<(u32, u32), &XlsxCell> = cells
            .iter()
            .map(|cell| ((cell.col, cell.row), cell))
            .collect();
        book.unshare(&part, &|group: &SharedGroup| {
            cells_written
                .get(&group.anchor)
                .is_some_and(|change| !format_only(change, stored.get(&group.anchor).copied()))
        })?;
    }
    Ok(())
}

/// Have the opening application recalculate every formula on load: the
/// projection's fallback when the engine cannot recalculate the workbook.
pub fn mark_full_calc(
    bytes: &[u8],
    limits: Limits,
    resources: &crate::resource::Resources,
) -> Result<Vec<u8>> {
    let mut book = Book::open(bytes, limits, resources)?;
    let source = book
        .package
        .part(&book.part)?
        .ok_or(refused("the workbook part is missing"))?;
    let tree = XmlTree::parse(&source, resources)?;
    let value = match tree.child(0, SML, "calcPr")? {
        Some((_, node)) => match node.attr_spans.get("fullCalcOnLoad") {
            Some(span) => [
                &source[..span.start],
                &b"fullCalcOnLoad=\"1\""[..],
                &source[span.end..],
            ]
            .concat(),
            None => {
                let open = &source[node.span.start..node.open_end];
                let end = node.open_end - if open.ends_with(b"/>") { 2 } else { 1 };
                [
                    &source[..end],
                    &b" fullCalcOnLoad=\"1\""[..],
                    &source[end..],
                ]
                .concat()
            }
        },
        None => {
            let at = insertion(
                &tree,
                &[
                    "sheets",
                    "functionGroups",
                    "externalReferences",
                    "definedNames",
                ],
            )
            .ok_or(refused("the workbook has no sheet list"))?;
            let element = format!(
                "<{} fullCalcOnLoad=\"1\"/>",
                tree.nodes[0].child_name("calcPr")
            );
            [&source[..at], element.as_bytes(), &source[at..]].concat()
        }
    };
    book.package.replace_xml_part(&book.part, value)?;
    Ok(book.package.export()?)
}

impl Book {
    /// Write the body's cell formats into the stylesheet: each one's index in
    /// `cellXfs`, in order. A workbook with none gets a minimal one first.
    /// The workbook's formats are read again after.
    pub(super) fn resolve_formats(&mut self, formats: &[XlsxFormat]) -> Result<Vec<u32>> {
        let part = match self.styles_part.clone() {
            Some(part) => part,
            None if formats.is_empty() => return Ok(Vec::new()),
            None => self.seed_styles()?,
        };
        let bytes = self
            .package
            .part(&part)?
            .ok_or(refused("a workbook part is missing"))?;
        let (indices, value, added) =
            write_formats(&bytes, self.package.resources(), formats, self.styles.len())?;
        // Excel applies only a style the workbook has; the nearest it does
        // not refuse is to add one, and the receipt says so.
        for name in added {
            self.effects.push(format!(
                "cell_style_added: {name}; the workbook had no such style, so it was added with the look of the cell format it was first applied to"
            ));
        }
        if let Some(value) = value {
            self.package.replace_xml_part(&part, value)?;
            self.styles = styles(&parse(&self.package, &part)?)?;
        }
        Ok(indices)
    }

    /// Add a stylesheet beside the workbook part, related from it, whose one
    /// cell format is the default every cell read in (General, the one font,
    /// no fill, no border), as Excel writes a new workbook's.
    pub(super) fn seed_styles(&mut self) -> Result<String> {
        const STYLES_TYPE: &str =
            "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml";
        let dir = self.part.rsplit_once('/').map_or("", |(dir, _)| dir);
        let mut n = 0_u32;
        let name = loop {
            let file = if n == 0 {
                "styles.xml".to_owned()
            } else {
                format!("styles{n}.xml")
            };
            let name = if dir.is_empty() {
                file
            } else {
                format!("{dir}/{file}")
            };
            if self.package.part(&name)?.is_none() {
                break name;
            }
            n += 1;
        };
        let sheet = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<styleSheet xmlns=\"{SML}\"><fonts count=\"1\"><font><sz val=\"11\"/><name val=\"Calibri\"/></font></fonts><fills count=\"2\"><fill><patternFill patternType=\"none\"/></fill><fill><patternFill patternType=\"gray125\"/></fill></fills><borders count=\"1\"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs><cellXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/></cellXfs><cellStyles count=\"1\"><cellStyle name=\"Normal\" xfId=\"0\" builtinId=\"0\"/></cellStyles></styleSheet>"
        );
        self.package
            .add_part(&name, STYLES_TYPE, sheet.into_bytes())?;
        self.package
            .relate(&self.part, &format!("{REL}/styles"), &name)?;
        self.styles_part = Some(name.clone());
        self.styles = styles(&parse(&self.package, &name)?)?;
        Ok(name)
    }

    /// Write the changed names into `definedNames` (FIX 8572): a changed
    /// name keeps its element, and only its spelling, hidden flag and
    /// formula text change where they differ; a deleted one goes; a new one
    /// is added at the list's end. The list's other names and markup keep
    /// their bytes, and the list goes only with the last of its contents.
    pub(super) fn rewrite_names(&mut self, changes: &[&XlsxChange]) -> Result<()> {
        let bytes = self
            .package
            .part(&self.part)?
            .ok_or(refused("the workbook part is missing"))?;
        let tree = XmlTree::parse(&bytes, self.package.resources())?;
        let root = &tree.nodes[0];
        let mut pending: Vec<((String, Option<usize>), Option<retain::NameWrite<'_>>)> = Vec::new();
        for change in changes {
            let (name, sheet, write) = match change {
                XlsxChange::SetName {
                    name,
                    sheet,
                    formula,
                    hidden,
                } => {
                    check_name(name)?;
                    check_cell(&XlsxValue::Blank, Some(formula))?;
                    let write = retain::NameWrite {
                        name,
                        formula,
                        hidden: *hidden,
                    };
                    (name, sheet, Some(write))
                }
                XlsxChange::DeleteName { name, sheet } => (name, sheet, None),
                XlsxChange::Cell { .. }
                | XlsxChange::Sheets { .. }
                | XlsxChange::Shift { .. }
                | XlsxChange::Formats { .. }
                | XlsxChange::RenameColumn { .. } => {
                    continue;
                }
            };
            let key = (
                name.to_lowercase(),
                local_sheet(&self.order, sheet.as_deref())?,
            );
            if pending.iter().any(|(held, _)| *held == key) {
                return Err(refused("two changes write one name"));
            }
            pending.push((key, write));
        }
        let list = tree.child(0, SML, "definedNames")?;
        let mut edits = Vec::new();
        // The list's elements that stay.
        let mut kept = 0;
        if let Some((list, _)) = list {
            for (_, node) in tree.children(list) {
                if !node.is(SML, "definedName") {
                    kept += 1;
                    continue;
                }
                let name = node.attr("name").unwrap_or_default().to_lowercase();
                let local = node
                    .attr("localSheetId")
                    .and_then(|at| at.trim().parse::<usize>().ok());
                let Some(at) = pending
                    .iter()
                    .position(|(key, _)| key.0 == name && key.1 == local)
                else {
                    kept += 1;
                    continue;
                };
                if name.starts_with("_xlnm.") {
                    return Err(refused("a built-in name is read-only"));
                }
                match pending.remove(at).1 {
                    Some(write) => {
                        kept += 1;
                        edits.extend(retain::name_patch(&bytes, node, &write)?);
                    }
                    None => edits.push((node.span.clone(), Vec::new())),
                }
            }
        }
        let element = match list {
            Some((_, node)) => node.child_name("definedName"),
            None => root.child_name("definedName"),
        };
        let mut added = Vec::new();
        for ((_, local), write) in pending {
            let write = write.ok_or(refused("no such defined name"))?;
            added.extend(write.xml(&element, local).into_bytes());
        }
        match list {
            Some((_, node)) if kept == 0 && added.is_empty() => {
                edits = vec![(node.span.clone(), Vec::new())];
            }
            Some((_, node)) => {
                if !added.is_empty() {
                    edits.push(insert_end(&bytes, node, &added));
                }
            }
            None if added.is_empty() => {}
            None => {
                let at = insertion(&tree, &["sheets", "functionGroups", "externalReferences"])
                    .ok_or(refused("the workbook has no sheet list"))?;
                let wrapper = root.child_name("definedNames");
                let mut list = format!("<{wrapper}>").into_bytes();
                list.extend(added);
                list.extend(format!("</{wrapper}>").into_bytes());
                edits.push((at..at, list));
            }
        }
        if edits.is_empty() {
            return Ok(());
        }
        let value = splice(&bytes, edits)
            .map_err(|_| refused("the workbook part could not be rewritten"))?;
        self.package.replace_xml_part(&self.part, value)?;
        Ok(())
    }
}
