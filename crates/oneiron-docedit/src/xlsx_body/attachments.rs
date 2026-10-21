//! Drawing, note, table and slicer changes after an axis edit.
//! Entry: `Book::move_anchors`.
//! Definitions live here; xlsx_body retains the old API and shared Book state.

use super::*;

impl Book {
    /// Move a worksheet drawing's objects by a row or column edit to `sheet`,
    /// as Excel places them: a two-cell anchor moves and sizes with its cells
    /// (`editAs` twoCell, the default) or moves alone (oneCell), a one-cell
    /// anchor moves, and an absolute one stays. An object sized by cells the
    /// edit deletes collapses where they were, as Excel's does, and the
    /// effects name it.
    pub(super) fn move_anchors(
        &mut self,
        sheet: &str,
        part: &str,
        edit: &XlsxAxisEdit,
    ) -> Result<()> {
        let Some(bytes) = self.package.part(part)? else {
            return Ok(());
        };
        let tree = XmlTree::parse(&bytes, self.package.limits().xml)?;
        let (line, offset, lines, last) = match edit.axis {
            XlsxAxis::Row => ("row", "rowOff", "rows", MAX_ROW),
            XlsxAxis::Column => ("col", "colOff", "columns", MAX_COLUMN),
        };
        // One end of an anchor: its row or column node and 1-based number,
        // and its offset node.
        let marker = |anchor: usize, end: &str| -> Option<(usize, u32, Option<usize>)> {
            let (at, _) = tree.child(anchor, XDR, end).ok()??;
            let (node, value) = tree.child(at, XDR, line).ok()??;
            let number = value.text.trim().parse::<u32>().ok()?.checked_add(1)?;
            let nudge = tree
                .child(at, XDR, offset)
                .ok()?
                .filter(|(_, node)| !node.empty)
                .map(|(at, _)| at);
            (!value.empty).then_some((node, number, nudge))
        };
        // Where an end lands, and whether the edit deleted its cell.
        let place = |n: u32| match edit.moved(n) {
            Some(to) => (to, false),
            None if edit.delete => (edit.at, true),
            None => (last, false),
        };
        let mut edits = Vec::new();
        for (index, anchor) in tree.nodes.iter().enumerate() {
            if anchor.namespace != XDR {
                continue;
            }
            let sizes = match anchor.name.as_str() {
                "twoCellAnchor" => match anchor.attr("editAs") {
                    Some("absolute") => continue,
                    Some("oneCell") => false,
                    _ => true,
                },
                "oneCellAnchor" => false,
                _ => continue,
            };
            let Some((from, first, from_offset)) = marker(index, "from") else {
                continue;
            };
            let to = marker(index, "to");
            // Each end's node, old and new number, and the offset a deleted
            // cell resets.
            let mut ends = Vec::new();
            let (moved, cut) = place(first);
            if sizes {
                let Some((to, end, to_offset)) = to else {
                    continue;
                };
                let (moved_end, cut_end) = place(end);
                ends.push((from, first, moved, from_offset.filter(|_| cut)));
                ends.push((to, end, moved_end, to_offset.filter(|_| cut_end)));
                if cut && cut_end {
                    let name = tree.nodes[index..]
                        .iter()
                        .take_while(|node| node.span.start < anchor.span.end)
                        .find(|node| node.name == "cNvPr")
                        .and_then(|node| node.attr("name"))
                        .unwrap_or("an object");
                    self.effects.push(format!(
                        "drawing_collapsed: {sheet}, {name}; the {lines} it spanned were deleted"
                    ));
                }
            } else {
                ends.push((from, first, moved, None));
                if let Some((to, end, _)) = to {
                    let shifted = i64::from(end) + i64::from(moved) - i64::from(first);
                    let shifted = shifted.clamp(1, i64::from(last)) as u32;
                    ends.push((to, end, shifted, None));
                }
            }
            for (node, old, new, reset) in ends {
                if new != old {
                    edits.push((
                        tree.nodes[node].content.clone(),
                        (new - 1).to_string().into_bytes(),
                    ));
                }
                if let Some(reset) = reset {
                    edits.push((tree.nodes[reset].content.clone(), b"0".to_vec()));
                }
            }
        }
        if edits.is_empty() {
            return Ok(());
        }
        let value =
            splice(&bytes, edits).map_err(|_| refused("a drawing could not be rewritten"))?;
        self.package.replace_xml_part(part, value)?;
        Ok(())
    }

    /// Move a worksheet's note shapes (its legacy VML drawing) by a row or
    /// column edit to `sheet`: each note's cell, its box beside it. A note
    /// whose cell the edit deletes goes, as its comment does, and the effects
    /// name it. Form controls and other shapes stay as written.
    pub(super) fn move_notes(
        &mut self,
        sheet: &str,
        part: &str,
        edit: &XlsxAxisEdit,
    ) -> Result<()> {
        let Some(bytes) = self.package.part(part)? else {
            return Ok(());
        };
        // An older writer's VML need not be XML; its shapes stay as written.
        let Ok(tree) = XmlTree::parse(&bytes, self.package.limits().xml) else {
            self.effects.push(format!(
                "note_shapes_kept: {sheet}, {part}; the drawing does not read as XML"
            ));
            return Ok(());
        };
        let mut edits = Vec::new();
        for (index, data) in tree.nodes.iter().enumerate() {
            if !data.is(VML_EXCEL, "ClientData") || data.attr("ObjectType") != Some("Note") {
                continue;
            }
            let field = |name: &str| {
                tree.child(index, VML_EXCEL, name)
                    .ok()
                    .flatten()
                    .filter(|(_, node)| !node.empty)
            };
            let (Some((row_at, row)), Some((col_at, col))) = (field("Row"), field("Column")) else {
                continue;
            };
            let (Ok(row), Ok(col)) = (
                row.text.trim().parse::<u32>(),
                col.text.trim().parse::<u32>(),
            ) else {
                continue;
            };
            // Zero-based.
            let at = (col + 1, row + 1);
            let Some(to) = edit.cell(at) else {
                if let Some(shape) = data.parent {
                    edits.push((tree.nodes[shape].span.clone(), Vec::new()));
                }
                self.effects
                    .push(format!("note_removed: {sheet}, {}", a1(at.0, at.1)));
                continue;
            };
            if to == at {
                continue;
            }
            edits.push((
                tree.nodes[row_at].content.clone(),
                (to.1 - 1).to_string().into_bytes(),
            ));
            edits.push((
                tree.nodes[col_at].content.clone(),
                (to.0 - 1).to_string().into_bytes(),
            ));
            // The box: left column and offset, top row and offset, then the
            // right column and bottom row with theirs.
            let Some((box_at, anchor)) = field("Anchor") else {
                continue;
            };
            let Some(mut corners) = anchor
                .text
                .split(',')
                .map(|value| value.trim().parse::<i64>().ok())
                .collect::<Option<Vec<i64>>>()
                .filter(|values| values.len() == 8)
            else {
                continue;
            };
            let (across, down) = (
                i64::from(to.0) - i64::from(at.0),
                i64::from(to.1) - i64::from(at.1),
            );
            for (value, by, last) in [
                (0, across, MAX_COLUMN),
                (4, across, MAX_COLUMN),
                (2, down, MAX_ROW),
                (6, down, MAX_ROW),
            ] {
                corners[value] = (corners[value] + by).clamp(0, i64::from(last) - 1);
            }
            let text = corners
                .iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            edits.push((tree.nodes[box_at].content.clone(), text.into_bytes()));
        }
        if edits.is_empty() {
            return Ok(());
        }
        let value =
            splice(&bytes, edits).map_err(|_| refused("a note drawing could not be rewritten"))?;
        self.package.replace_xml_part(part, value)?;
        Ok(())
    }

    /// Add or remove a table's columns for a column edit inside it, as Excel
    /// does, before its range moves: an inserted column takes a new id and
    /// the first free `ColumnN` name, and a deleted one goes with its
    /// calculated and totals formulas. An edit at or past either edge only
    /// moves the table, and one that deletes all of it refuses when the range
    /// moves. The header cells the inserted columns' names go in, as cell
    /// changes to sheet `sheet`; the columns it deletes are added to `lost`.
    pub(super) fn move_table_columns(
        &mut self,
        sheet: &str,
        part: &str,
        edit: &XlsxAxisEdit,
        lost: &mut Vec<LostColumns>,
    ) -> Result<Vec<XlsxChange>> {
        if edit.axis != XlsxAxis::Column {
            return Ok(Vec::new());
        }
        let bytes = self
            .package
            .part(part)?
            .ok_or(refused("a workbook part is missing"))?;
        let tree = XmlTree::parse(&bytes, self.package.limits().xml)?;
        let root = &tree.nodes[0];
        let Some(range) = root
            .attr("ref")
            .filter(|_| root.is(SML, "table"))
            .and_then(|reference| XlsxArea::parse(reference, XlsxLock::TableRow))
        else {
            return Ok(Vec::new());
        };
        // The place in the table the columns go in at or are deleted from.
        let Some(at) = column_span(range.first.0, range.last.0, edit) else {
            return Ok(Vec::new());
        };
        if root
            .attr("tableType")
            .is_some_and(|kind| kind != "worksheet")
        {
            return Err(refused("a column edit inside a query or XML table"));
        }
        let (list, list_node) = tree
            .child(0, SML, "tableColumns")?
            .ok_or(refused("a table has no columns"))?;
        let columns: Vec<&Node> = tree
            .children(list)
            .filter(|(_, node)| node.is(SML, "tableColumn"))
            .map(|(_, node)| node)
            .collect();
        if columns.len() != (range.last.0 - range.first.0 + 1) as usize {
            return Err(refused("a table's columns do not match its range"));
        }
        let mut edits = Vec::new();
        let mut headers = Vec::new();
        let count = if edit.delete {
            for column in &columns[at.clone()] {
                edits.push((column.span.clone(), Vec::new()));
            }
            if let Some(id) = root.attr("id").and_then(|id| id.trim().parse::<u32>().ok()) {
                lost.push(LostColumns {
                    id,
                    name: root
                        .attr("displayName")
                        .or_else(|| root.attr("name"))
                        .unwrap_or_default()
                        .to_owned(),
                    columns: columns[at.clone()]
                        .iter()
                        .filter_map(|column| {
                            Some((
                                column.attr("id")?.trim().parse::<u32>().ok()?,
                                column.attr("name").unwrap_or_default().to_owned(),
                            ))
                        })
                        .collect(),
                });
            }
            columns.len() - at.len()
        } else {
            let taken: Vec<String> = columns
                .iter()
                .filter_map(|column| column.attr("name"))
                .map(str::to_owned)
                .collect();
            let mut id = columns
                .iter()
                .filter_map(|column| column.attr("id")?.trim().parse::<u32>().ok())
                .max()
                .unwrap_or(0);
            let element = list_node.child_name("tableColumn");
            let header = root
                .attr("headerRowCount")
                .and_then(|count| count.trim().parse::<u32>().ok())
                .unwrap_or(1)
                > 0;
            let mut added = String::new();
            for (col, name) in (edit.at..).zip(free_column_names(&taken, edit.count)) {
                id += 1;
                added.push_str(&format!(
                    "<{element} id=\"{id}\" name=\"{}\"/>",
                    escape_attribute(&name)
                ));
                if header {
                    headers.push(XlsxChange::Cell {
                        sheet: sheet.to_owned(),
                        col,
                        row: range.first.1,
                        value: XlsxValue::Text(name),
                        formula: None,
                        style: None,
                    });
                }
            }
            let point = columns[at.start].span.start;
            edits.push((point..point, added.into_bytes()));
            columns.len() + edit.count as usize
        };
        edits.push(set_attribute(
            &bytes,
            list_node,
            "count",
            &count.to_string(),
        ));
        let value = splice(&bytes, edits).map_err(|_| refused("a table could not be rewritten"))?;
        self.package.replace_xml_part(part, value)?;
        Ok(headers)
    }

    /// Remove the slicers of the table columns a column edit deleted, as
    /// Excel does: each one's cache with its workbook registration and
    /// defined name, its slicer views on whichever worksheet shows them, and
    /// the drawn shapes that show them. The effects name each.
    pub(super) fn drop_table_slicers(&mut self, lost: &[LostColumns]) -> Result<()> {
        let limits = self.package.limits().xml;
        // Each bound cache: its relationship id and name, and the table and
        // column it filtered.
        let mut caches: Vec<(String, String, String, String)> = Vec::new();
        for rel in self.package.relationships(&self.part)? {
            if rel.external || !rel.kind.ends_with("/slicerCache") {
                continue;
            }
            let Some(bytes) = self.package.part(&rel.target)? else {
                continue;
            };
            let tree = XmlTree::parse(&bytes, limits)?;
            let number = |node: &Node, name: &str| {
                node.attr(name).and_then(|v| v.trim().parse::<u32>().ok())
            };
            // A table slicer names its table and column by id.
            let Some(source) = tree
                .nodes
                .iter()
                .find(|node| node.name == "tableSlicerCache")
            else {
                continue;
            };
            let (Some(table), Some(column)) = (number(source, "tableId"), number(source, "column"))
            else {
                continue;
            };
            let Some((table, column)) =
                lost.iter()
                    .filter(|lost| lost.id == table)
                    .find_map(|lost| {
                        let (_, name) = lost.columns.iter().find(|(id, _)| *id == column)?;
                        Some((lost.name.clone(), name.clone()))
                    })
            else {
                continue;
            };
            let name = tree.nodes[0].attr("name").unwrap_or_default().to_owned();
            caches.push((rel.id, name, table, column));
        }
        if caches.is_empty() {
            return Ok(());
        }
        let names: HashSet<String> = caches.iter().map(|(_, name, ..)| name.clone()).collect();
        // Each removed view: its cache, sheet and name.
        let mut views: Vec<(String, String, String)> = Vec::new();
        // The links that go, by their source part.
        let mut unlinks: Vec<(String, String)> = Vec::new();
        for (sheet, part) in self.worksheets.clone() {
            let rels = self.package.relationships(&part)?;
            let mut shown = HashSet::new();
            for rel in rels
                .iter()
                .filter(|rel| !rel.external && rel.kind.ends_with("/slicer"))
            {
                let Some(bytes) = self.package.part(&rel.target)? else {
                    continue;
                };
                let tree = XmlTree::parse(&bytes, limits)?;
                let slicers: Vec<&Node> = tree
                    .children(0)
                    .map(|(_, node)| node)
                    .filter(|node| node.name == "slicer")
                    .collect();
                let bound = |node: &Node| {
                    node.attr("cache")
                        .is_some_and(|cache| names.contains(cache))
                };
                let gone: Vec<&Node> = slicers.iter().copied().filter(|node| bound(node)).collect();
                if gone.is_empty() {
                    continue;
                }
                for slicer in &gone {
                    let name = slicer.attr("name").unwrap_or_default().to_owned();
                    views.push((
                        slicer.attr("cache").unwrap_or_default().to_owned(),
                        sheet.clone(),
                        name.clone(),
                    ));
                    shown.insert(name);
                }
                if gone.len() == slicers.len() {
                    // The part goes, with the sheet's registration of it.
                    let id = rel.id.clone();
                    self.drop_nodes(&part, &|tree: &XmlTree, at: usize| {
                        let node = &tree.nodes[at];
                        node.name == "slicer" && node.attr_ns(REL, "id") == Some(id.as_str())
                    })?;
                    unlinks.push((part.clone(), rel.id.clone()));
                } else {
                    self.drop_nodes(&rel.target, &|tree: &XmlTree, at: usize| {
                        tree.nodes[at].parent == Some(0) && bound(&tree.nodes[at])
                    })?;
                }
            }
            if shown.is_empty() {
                continue;
            }
            for drawing in rels
                .iter()
                .filter(|rel| !rel.external && rel.kind.ends_with("/drawing"))
            {
                self.drop_nodes(&drawing.target, &|tree: &XmlTree, at: usize| {
                    let anchor = &tree.nodes[at];
                    anchor.parent == Some(0)
                        && tree.nodes[at + 1..]
                            .iter()
                            .take_while(|node| node.span.start < anchor.span.end)
                            .any(|node| {
                                node.name == "slicer"
                                    && node.attr("name").is_some_and(|name| shown.contains(name))
                            })
                })?;
            }
        }
        let ids: HashSet<String> = caches.iter().map(|(id, ..)| id.clone()).collect();
        let book = self.part.clone();
        self.drop_nodes(&book, &|tree: &XmlTree, at: usize| {
            let node = &tree.nodes[at];
            (node.name == "slicerCache"
                && node.attr_ns(REL, "id").is_some_and(|id| ids.contains(id)))
                || (node.is(SML, "definedName")
                    && node.attr("name").is_some_and(|name| names.contains(name)))
        })?;
        unlinks.extend(ids.into_iter().map(|id| (book.clone(), id)));
        let before = self.package.reachable("")?;
        for (source, id) in &unlinks {
            self.package.unrelate(source, id)?;
        }
        let after = self.package.reachable("")?;
        for part in before.difference(&after) {
            if self.package.names().any(|name| name == part.as_str()) {
                self.package.remove_part(part)?;
            }
        }
        self.package.prune_defaults()?;
        for (_, cache, table, column) in &caches {
            let shown: Vec<String> = views
                .iter()
                .filter(|(of, ..)| of == cache)
                .map(|(_, sheet, name)| format!("{name} on {sheet}"))
                .collect();
            let shown = if shown.is_empty() {
                String::new()
            } else {
                format!(" ({})", shown.join(", "))
            };
            self.effects.push(format!(
                "slicer_removed: {cache}{shown}; table {table} lost its column {column}"
            ));
        }
        Ok(())
    }

    /// Remove from `part` each element `pick` names, with each list, `ext`
    /// or `extLst` the removal empties. How many `pick` named.
    pub(super) fn drop_nodes(
        &mut self,
        part: &str,
        pick: &dyn Fn(&XmlTree, usize) -> bool,
    ) -> Result<usize> {
        /// Containers that go with their last entry.
        const LISTS: &[&str] = &[
            "slicerCaches",
            "slicerList",
            "definedNames",
            "ext",
            "extLst",
        ];
        let Some(bytes) = self.package.part(part)? else {
            return Ok(0);
        };
        let tree = XmlTree::parse(&bytes, self.package.limits().xml)?;
        let mut removed: HashSet<usize> = (1..tree.nodes.len())
            .filter(|at| pick(&tree, *at))
            .collect();
        let picked = removed.len();
        if picked == 0 {
            return Ok(0);
        }
        // Children come after their parents.
        for index in (1..tree.nodes.len()).rev() {
            let node = &tree.nodes[index];
            if LISTS.contains(&node.name.as_str())
                && !node.children.is_empty()
                && node.children.iter().all(|child| removed.contains(child))
            {
                removed.insert(index);
            }
        }
        let inside = |mut at: Option<usize>| {
            while let Some(node) = at {
                if removed.contains(&node) {
                    return true;
                }
                at = tree.nodes[node].parent;
            }
            false
        };
        let edits: Vec<Splice> = removed
            .iter()
            .filter(|index| !inside(tree.nodes[**index].parent))
            .map(|index| (tree.nodes[*index].span.clone(), Vec::new()))
            .collect();
        let value = splice(&bytes, edits).map_err(|_| refused("a part could not be rewritten"))?;
        self.package.replace_xml_part(part, value)?;
        Ok(picked)
    }
}
