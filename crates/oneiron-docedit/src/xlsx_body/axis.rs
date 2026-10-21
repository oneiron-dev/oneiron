//! Shared-formula expansion and worksheet axis changes.
//! Entry: `Book::shift`.
//! Definitions live here; xlsx_body retains the old API and shared Book state.

use super::*;

impl Book {
    /// Write every shared formula out cell by cell, each member with its own
    /// text in place (a rich value's metadata stays with its cell), so a row
    /// or column edit moves each cell's references alone. A group whose
    /// members cannot all be read refuses.
    pub(super) fn unshare_all(&mut self) -> Result<()> {
        let parts: Vec<String> = self.worksheets.values().cloned().collect();
        for part in parts {
            let (cells, _, _) = self.sheet(&part)?;
            if cells
                .iter()
                .any(|cell| cell.locked == Some(XlsxLock::SharedFormula))
            {
                return Err(refused(
                    "a shared formula whose members cannot all be written out",
                ));
            }
            self.unshare(&part, &|_: &SharedGroup| true)?;
        }
        Ok(())
    }

    /// Write each `chosen` shared formula group of one worksheet out as its
    /// members' own formulas, in place: every other byte of each cell (its
    /// cached value, rich value metadata and format) stays. A chosen group
    /// whose members cannot all be written out refuses.
    pub(super) fn unshare(
        &mut self,
        part: &str,
        pick: &dyn Fn(&SharedGroup) -> bool,
    ) -> Result<()> {
        let (cells, _, groups) = self.sheet(part)?;
        let chosen: HashSet<u32> = groups
            .iter()
            .filter(|(_, group)| pick(group))
            .map(|(si, _)| *si)
            .collect();
        if chosen.is_empty() {
            return Ok(());
        }
        if chosen.iter().any(|si| !groups[si].complete) {
            return Err(refused(
                "a shared formula whose members cannot all be written out",
            ));
        }
        let own: HashMap<(u32, u32), &str> = cells
            .iter()
            .filter_map(|cell| Some(((cell.col, cell.row), cell.formula.as_deref()?)))
            .collect();
        let bytes = self
            .package
            .part(part)?
            .ok_or(refused("a worksheet part is missing"))?;
        let tree = XmlTree::parse(&bytes, self.package.limits().xml)?;
        let mut edits = Vec::new();
        for node in &tree.nodes {
            if !node.is(SML, "f")
                || node.attr("t") != Some("shared")
                || !node
                    .attr("si")
                    .and_then(|si| si.trim().parse::<u32>().ok())
                    .is_some_and(|si| chosen.contains(&si))
            {
                continue;
            }
            let at = node
                .parent
                .and_then(|cell| tree.nodes[cell].attr("r"))
                .and_then(cell_ref)
                .ok_or(refused("a worksheet cell has no reference"))?;
            let text = own
                .get(&at)
                .ok_or(refused("a shared formula member is missing"))?;
            // Only the group's attributes go and the text changes; the
            // formula's other attributes stay (FIX 8571).
            for attr in ["t", "si", "ref"] {
                edits.extend(drop_attribute(&bytes, node, attr));
            }
            edits.extend(
                replace_text(&bytes, node, &storage_form(text))
                    .ok_or(refused("a worksheet could not be rewritten"))?,
            );
        }
        let value =
            splice(&bytes, edits).map_err(|_| refused("a worksheet could not be rewritten"))?;
        self.package.replace_xml_part(part, value)?;
        Ok(())
    }

    /// Insert or delete rows or columns in one worksheet, as Excel does. Its
    /// rows and cells, merged ranges, conditional formats, validations,
    /// hyperlinks, filters, column widths, page breaks, views and panes,
    /// data table inputs, tables, comments and their note shapes, drawn
    /// objects and the pivot caches sourced from it move; what the edit
    /// deletes goes, and a range that loses part of itself shrinks. A table
    /// gains or loses the columns inserted or deleted inside it, and a
    /// deleted column's slicers go with it. Then every formula, chart range,
    /// hyperlink location and defined name that reaches the sheet follows, a
    /// reference to a deleted cell reading `#REF!`. Shared formulas must be
    /// written out first.
    pub(super) fn shift(&mut self, sheet: &str, edit: &XlsxAxisEdit) -> Result<()> {
        if !edit.fits() {
            return Err(refused("rows or columns off the sheet"));
        }
        let part = self
            .worksheets
            .get(sheet)
            .ok_or(refused("no such worksheet"))?
            .clone();
        let mut parts = vec![part.clone()];
        let mut tables = Vec::new();
        let mut drawings = Vec::new();
        let mut notes = Vec::new();
        for rel in self.package.relationships(&part)? {
            if rel.external {
                continue;
            }
            if rel.kind.ends_with("/table") {
                tables.push(rel.target.clone());
            }
            if rel.kind.ends_with("/drawing") {
                drawings.push(rel.target.clone());
            }
            if rel.kind.ends_with("/vmlDrawing") {
                notes.push(rel.target.clone());
            }
            if ["/table", "/comments", "/threadedComment"]
                .iter()
                .any(|kind| rel.kind.ends_with(kind))
            {
                parts.push(rel.target);
            }
        }
        let before = self.tables(&part)?;
        // Each table's first data row as the edit moves it, by its name in
        // lower case: an inserted row's calculated formulas are read there
        // (FIX 3695).
        let anchors: Vec<(String, u32)> = before
            .iter()
            .filter_map(|table| {
                let anchor = edit.moved(table.first.1.checked_add(table.header_rows)?)?;
                Some((table.name.to_lowercase(), anchor))
            })
            .collect();
        // The tables that lose columns, as they were, for the structured
        // references that name them.
        let dropped: Vec<(XlsxTable, Vec<String>)> = before
            .into_iter()
            .filter_map(|table| {
                let deleted = table.shifted(edit)?.deleted;
                (!deleted.is_empty()).then_some((table, deleted))
            })
            .collect();
        let mut headers = Vec::new();
        let mut lost = Vec::new();
        for table in &tables {
            headers.extend(self.move_table_columns(sheet, table, edit, &mut lost)?);
        }
        for target in &parts {
            self.move_coordinates(sheet, target, edit)?;
        }
        self.inherit_lines(&part, edit)?;
        for drawing in &drawings {
            self.move_anchors(sheet, drawing, edit)?;
        }
        for drawing in &notes {
            self.move_notes(sheet, drawing, edit)?;
        }
        let lower = sheet.to_lowercase();
        self.move_pivot_sources(&|source: &Node| {
            let (Some(name), Some(reference)) = (source.attr("sheet"), source.attr("ref")) else {
                return SourceFate::Keep;
            };
            if name.to_lowercase() != lower {
                return SourceFate::Keep;
            }
            match moved_area(reference, edit) {
                Some(Some(to)) if to != reference => SourceFate::Range(to),
                Some(None) => SourceFate::Lost(format!("{name}!{reference}")),
                _ => SourceFate::Keep,
            }
        })?;
        if !lost.is_empty() {
            self.drop_table_slicers(&lost)?;
            self.note_pivot_fields(&lost)?;
        }
        // An inserted table column's header cell holds its name, in the
        // format of the header cell to its left.
        if !headers.is_empty() {
            let (cells, _, _) = self.sheet(&part)?;
            let left: HashMap<u32, Option<u32>> = cells
                .iter()
                .filter(|cell| cell.col + 1 == edit.at)
                .map(|cell| (cell.row, cell.style))
                .collect();
            for header in &mut headers {
                if let XlsxChange::Cell { row, style, .. } = header {
                    *style = left.get(&*row).copied().flatten();
                }
            }
            let mut rows: BTreeMap<u32, BTreeMap<u32, &XlsxChange>> = BTreeMap::new();
            for header in &headers {
                if let XlsxChange::Cell { col, row, .. } = header {
                    rows.entry(*row).or_default().insert(*col, header);
                }
            }
            let bytes = rewrite_rows(&self.package, &part, &rows, &BTreeSet::new())?;
            self.package.replace_xml_part(&part, bytes)?;
        }
        // Each part with formulas follows, an unqualified structured
        // reference to the table it belongs to (FIX 3438).
        for home in self.formula_homes()? {
            self.rewrite_formulas(&home.part, &|text: &str, at| {
                shift_axis_formula(
                    text,
                    home.sheet.as_deref(),
                    sheet,
                    edit,
                    &dropped,
                    home.owner(at),
                )
            })?;
        }
        if !edit.delete && edit.axis == XlsxAxis::Row {
            self.fill_calculated(sheet, &part, edit, &anchors)?;
        }
        Ok(())
    }

    /// Each part with formulas, as [`FormulaHome`] reads it: every
    /// worksheet with its tables, every table part, the charts and the
    /// workbook's defined names.
    pub(super) fn formula_homes(&self) -> Result<Vec<FormulaHome>> {
        let mut homes = Vec::new();
        for (name, part) in &self.worksheets {
            homes.push(FormulaHome {
                part: part.clone(),
                sheet: Some(name.clone()),
                tables: self.tables(part)?,
                own: None,
            });
            for rel in self.package.relationships(part)? {
                if !rel.external && rel.kind.ends_with("/table") {
                    let table = parse(&self.package, &rel.target)?;
                    let root = &table.nodes[0];
                    homes.push(FormulaHome {
                        own: root
                            .attr("displayName")
                            .or_else(|| root.attr("name"))
                            .map(str::to_owned),
                        part: rel.target,
                        sheet: Some(name.clone()),
                        tables: Vec::new(),
                    });
                }
            }
        }
        homes.extend(
            self.package
                .names()
                .filter(|name| {
                    let lower = name.to_ascii_lowercase();
                    lower.contains("/charts/") && lower.ends_with(".xml")
                })
                .map(|name| FormulaHome {
                    part: name.to_owned(),
                    sheet: None,
                    tables: Vec::new(),
                    own: None,
                }),
        );
        homes.push(FormulaHome {
            part: self.part.clone(),
            sheet: None,
            tables: Vec::new(),
            own: None,
        });
        Ok(homes)
    }
}
