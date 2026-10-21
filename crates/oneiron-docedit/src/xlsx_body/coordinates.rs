//! Coordinate XML rewrites after an axis edit.
//! Entry: `Book::move_coordinates`.
//! Definitions live here; xlsx_body retains the old API and shared Book state.

use super::*;

impl Book {
    /// Move one part's cell coordinates by a row or column edit to worksheet
    /// `sheet`: a worksheet's rows, cells, ranges, page breaks, views and
    /// data table inputs, a table's range, a comment's cell. What the edit
    /// deletes goes, and a list it empties goes with it.
    pub(super) fn move_coordinates(
        &mut self,
        sheet: &str,
        part: &str,
        edit: &XlsxAxisEdit,
    ) -> Result<()> {
        /// Lists that go when the edit removes every entry.
        const LISTS: &[&str] = &[
            "mergeCells",
            "dataValidations",
            "hyperlinks",
            "cols",
            "conditionalFormattings",
            "protectedRanges",
            "ignoredErrors",
            "rowBreaks",
            "colBreaks",
            "ext",
            "extLst",
        ];
        let bytes = self
            .package
            .part(part)?
            .ok_or(refused("a workbook part is missing"))?;
        let tree = XmlTree::parse(&bytes, self.package.limits().xml)?;
        let mut removed: HashSet<usize> = HashSet::new();
        let mut sets: Vec<(usize, &'static str, String)> = Vec::new();
        let mut unsets: Vec<(usize, &'static str)> = Vec::new();
        let mut texts: Vec<(usize, String)> = Vec::new();
        let mut effects = Vec::new();
        // A view's panes that a frozen split losing all its rows or columns
        // takes with it, by the view.
        let mut gone_panes: HashMap<usize, &[&str]> = HashMap::new();
        let last_line = match edit.axis {
            XlsxAxis::Row => MAX_ROW,
            XlsxAxis::Column => MAX_COLUMN,
        };
        for (index, node) in tree.nodes.iter().enumerate() {
            let parent = node.parent.map(|parent| &tree.nodes[parent]);
            let sml = node.namespace == SML;
            match node.name.as_str() {
                "row" if sml && parent.is_some_and(|data| data.is(SML, "sheetData")) => {
                    if edit.axis == XlsxAxis::Column {
                        if node.attr("spans").is_some() {
                            unsets.push((index, "spans"));
                        }
                        continue;
                    }
                    let number = node
                        .attr("r")
                        .and_then(|r| r.trim().parse::<u32>().ok())
                        .ok_or(refused("a worksheet row has no number"))?;
                    match edit.moved(number) {
                        None => {
                            removed.insert(index);
                        }
                        Some(to) if to != number => sets.push((index, "r", to.to_string())),
                        Some(_) => {}
                    }
                }
                "c" if sml && parent.is_some_and(|row| row.is(SML, "row")) => {
                    let at = node
                        .attr("r")
                        .and_then(cell_ref)
                        .ok_or(refused("a worksheet cell has no reference"))?;
                    match edit.cell(at) {
                        None => {
                            removed.insert(index);
                        }
                        Some(to) if to != at => sets.push((index, "r", a1(to.0, to.1))),
                        Some(_) => {}
                    }
                }
                "f" | "dimension" | "mergeCell" | "hyperlink" | "autoFilter" | "sortState"
                | "sortCondition" | "table"
                    if sml =>
                {
                    // A data table's input cells; Excel flags one the edit
                    // deletes rather than naming another cell.
                    if node.name == "f" && node.attr("t") == Some("dataTable") {
                        let master = parent
                            .and_then(|cell| cell.attr("r"))
                            .and_then(cell_ref)
                            .and_then(|master| edit.cell(master));
                        for (input, deleted, number) in [("r1", "del1", 1), ("r2", "del2", 2)] {
                            let Some(at) = node.attr(input).and_then(cell_ref) else {
                                continue;
                            };
                            if node.attr(deleted).is_some_and(truthy) {
                                continue;
                            }
                            match edit.cell(at) {
                                None => {
                                    sets.push((index, deleted, "1".to_owned()));
                                    if let Some(master) = master {
                                        effects.push(format!(
                                            "data_table_input_deleted: {sheet}, {}, input {number}",
                                            a1(master.0, master.1)
                                        ));
                                    }
                                }
                                Some(to) if to != at => sets.push((index, input, a1(to.0, to.1))),
                                Some(_) => {}
                            }
                        }
                    }
                    let Some(reference) = node.attr("ref") else {
                        continue;
                    };
                    match moved_area(reference, edit) {
                        // Unreadable, so it stays as written.
                        None => {}
                        Some(Some(to)) if node.name == "mergeCell" && !to.contains(':') => {
                            removed.insert(index);
                        }
                        Some(Some(to)) => {
                            if to != reference {
                                sets.push((index, "ref", to));
                            }
                        }
                        Some(None) => match node.name.as_str() {
                            "dimension" => sets.push((index, "ref", "A1".to_owned())),
                            "table" => return Err(refused("a row or column edit deletes a table")),
                            // A formula's range goes with its cell.
                            "f" => {}
                            _ => {
                                removed.insert(index);
                            }
                        },
                    }
                }
                "conditionalFormatting" | "dataValidation" | "protectedRange" | "ignoredError"
                    if sml =>
                {
                    let Some(list) = node.attr("sqref") else {
                        continue;
                    };
                    let moved = moved_list(list, edit);
                    if moved.is_empty() {
                        removed.insert(index);
                    } else if moved != list {
                        sets.push((index, "sqref", moved));
                    }
                }
                // An x14 rule's or validation's ranges, as element text.
                "sqref" if !sml && node.children.is_empty() && !node.empty => {
                    let moved = moved_list(&node.text, edit);
                    if moved.is_empty() {
                        removed.extend(node.parent);
                    } else if moved != node.text {
                        texts.push((index, moved));
                    }
                }
                "col" if sml && edit.axis == XlsxAxis::Column => {
                    let bound =
                        |name: &str| node.attr(name).and_then(|v| v.trim().parse::<u32>().ok());
                    let (Some(min), Some(max)) = (bound("min"), bound("max")) else {
                        continue;
                    };
                    match edit.range(min, max) {
                        None => {
                            removed.insert(index);
                        }
                        Some((low, high)) => {
                            if low != min {
                                sets.push((index, "min", low.to_string()));
                            }
                            if high != max {
                                sets.push((index, "max", high.to_string()));
                            }
                        }
                    }
                }
                // A filter column is numbered from its filter's first column.
                "filterColumn" if sml && edit.axis == XlsxAxis::Column => {
                    let (Some(filter), Some(id)) = (
                        parent
                            .filter(|filter| filter.is(SML, "autoFilter"))
                            .and_then(|filter| filter.attr("ref"))
                            .and_then(|reference| {
                                XlsxArea::parse(reference, XlsxLock::Unsupported)
                            }),
                        node.attr("colId")
                            .and_then(|id| id.trim().parse::<u32>().ok()),
                    ) else {
                        continue;
                    };
                    match (
                        edit.moved(filter.first.0 + id),
                        edit.range(filter.first.0, filter.last.0),
                    ) {
                        (Some(to), Some((left, _))) => {
                            if to - left != id {
                                sets.push((index, "colId", (to - left).to_string()));
                            }
                        }
                        _ => {
                            removed.insert(index);
                        }
                    }
                }
                // A page break, zero-based: before row or column `id`, across
                // `min..=max` of the other axis.
                "brk" if sml => {
                    let Some(own) = parent.and_then(|list| match list.name.as_str() {
                        "rowBreaks" => Some(XlsxAxis::Row),
                        "colBreaks" => Some(XlsxAxis::Column),
                        _ => None,
                    }) else {
                        continue;
                    };
                    let number =
                        |name: &str| node.attr(name).and_then(|v| v.trim().parse::<u32>().ok());
                    if own == edit.axis {
                        let Some(id) = number("id") else {
                            continue;
                        };
                        match edit.moved(id + 1) {
                            None => {
                                removed.insert(index);
                            }
                            Some(to) if to != id + 1 => {
                                sets.push((index, "id", (to - 1).to_string()))
                            }
                            Some(_) => {}
                        }
                    } else if let (Some(min), Some(max)) = (number("min"), number("max")) {
                        match edit.range(min + 1, max + 1) {
                            None => {
                                removed.insert(index);
                            }
                            Some((low, high)) => {
                                if low != min + 1 {
                                    sets.push((index, "min", (low - 1).to_string()));
                                }
                                if high != max + 1 {
                                    sets.push((index, "max", (high - 1).to_string()));
                                }
                            }
                        }
                    }
                }
                "sheetView" | "customSheetView" if sml => {
                    if let Some(at) = node.attr("topLeftCell").and_then(cell_ref) {
                        let to = kept_cell(at, edit);
                        if to != at {
                            sets.push((index, "topLeftCell", a1(to.0, to.1)));
                        }
                    }
                }
                "pane" if sml => {
                    if let Some(at) = node.attr("topLeftCell").and_then(cell_ref) {
                        let to = kept_cell(at, edit);
                        if to != at {
                            sets.push((index, "topLeftCell", a1(to.0, to.1)));
                        }
                    }
                    // A frozen split counts the rows or columns it holds; a
                    // plain split is a distance, which no edit moves.
                    if !node
                        .attr("state")
                        .is_some_and(|state| state.starts_with("frozen"))
                    {
                        continue;
                    }
                    let (split, other) = match edit.axis {
                        XlsxAxis::Row => ("ySplit", "xSplit"),
                        XlsxAxis::Column => ("xSplit", "ySplit"),
                    };
                    let held = |name: &str| {
                        node.attr(name)
                            .and_then(|v| v.trim().parse::<f64>().ok())
                            .filter(|v| *v >= 1.0)
                            .map(|v| v as u32)
                    };
                    let Some(frozen) = held(split) else {
                        continue;
                    };
                    let kept = if edit.delete {
                        let end = edit.at + edit.count - 1;
                        frozen - (end.min(frozen) + 1).saturating_sub(edit.at)
                    } else if edit.at <= frozen {
                        (frozen + edit.count).min(last_line - 1)
                    } else {
                        frozen
                    };
                    if kept == frozen {
                        continue;
                    }
                    if kept > 0 {
                        sets.push((index, split, kept.to_string()));
                        continue;
                    }
                    // The split loses every row or column it froze, and the
                    // panes past it go.
                    let (gone, kept_pane): (&[&str], &[(&str, &str)]) = match edit.axis {
                        XlsxAxis::Row => (
                            &["bottomLeft", "bottomRight"],
                            &[("bottomLeft", "topLeft"), ("bottomRight", "topRight")],
                        ),
                        XlsxAxis::Column => (
                            &["topRight", "bottomRight"],
                            &[("topRight", "topLeft"), ("bottomRight", "bottomLeft")],
                        ),
                    };
                    let Some(view) = node.parent else {
                        continue;
                    };
                    if held(other).is_none() {
                        removed.insert(index);
                        gone_panes.insert(view, &["topRight", "bottomLeft", "bottomRight"]);
                        continue;
                    }
                    unsets.push((index, split));
                    if let Some((_, to)) = node
                        .attr("activePane")
                        .and_then(|active| kept_pane.iter().find(|(from, _)| *from == active))
                    {
                        sets.push((index, "activePane", (*to).to_owned()));
                    }
                    gone_panes.insert(view, gone);
                }
                "selection" if sml => {
                    let pane = node.attr("pane").unwrap_or("topLeft");
                    if node
                        .parent
                        .and_then(|view| gone_panes.get(&view))
                        .is_some_and(|gone| gone.contains(&pane))
                    {
                        removed.insert(index);
                        continue;
                    }
                    let active = node
                        .attr("activeCell")
                        .and_then(cell_ref)
                        .map(|at| (at, kept_cell(at, edit)));
                    if let Some((at, to)) = active
                        && to != at
                    {
                        sets.push((index, "activeCell", a1(to.0, to.1)));
                    }
                    let Some(list) = node.attr("sqref") else {
                        continue;
                    };
                    let holds = |reference: &str, (col, row): (u32, u32)| {
                        XlsxArea::parse(reference, XlsxLock::Unsupported)
                            .is_some_and(|area| area.contains(col, row))
                    };
                    let mut moved = moved_list(list, edit);
                    match active {
                        // The selection keeps its active cell.
                        Some((_, to)) if !moved.split_whitespace().any(|r| holds(r, to)) => {
                            moved = a1(to.0, to.1);
                        }
                        None if moved.is_empty() => moved = "A1".to_owned(),
                        _ => {}
                    }
                    if moved == list {
                        continue;
                    }
                    if let Some((_, to)) = active {
                        let id = moved
                            .split_whitespace()
                            .position(|r| holds(r, to))
                            .unwrap_or(0);
                        let held = node
                            .attr("activeCellId")
                            .and_then(|id| id.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if id != held {
                            sets.push((index, "activeCellId", id.to_string()));
                        }
                    }
                    sets.push((index, "sqref", moved));
                }
                "comment" | "threadedComment" => {
                    let Some(at) = node.attr("ref").and_then(cell_ref) else {
                        continue;
                    };
                    match edit.cell(at) {
                        None => {
                            removed.insert(index);
                        }
                        Some(to) if to != at => sets.push((index, "ref", a1(to.0, to.1))),
                        Some(_) => {}
                    }
                }
                _ => {}
            }
        }
        // Children come after their parents, so a list emptied by its
        // entries' removal is seen after them.
        for index in (0..tree.nodes.len()).rev() {
            let node = &tree.nodes[index];
            if LISTS.contains(&node.name.as_str())
                && !node.children.is_empty()
                && node.children.iter().all(|child| removed.contains(child))
            {
                removed.insert(index);
            }
        }
        for (index, node) in tree.nodes.iter().enumerate() {
            if removed.contains(&index) || node.attr("count").is_none() {
                continue;
            }
            let kept = node
                .children
                .iter()
                .filter(|child| !removed.contains(child))
                .count();
            if kept != node.children.len() {
                sets.push((index, "count", kept.to_string()));
            }
            if node.attr("manualBreakCount").is_some() && kept != node.children.len() {
                let manual = node
                    .children
                    .iter()
                    .filter(|child| {
                        !removed.contains(child)
                            && tree.nodes[**child].attr("man").is_some_and(truthy)
                    })
                    .count();
                sets.push((index, "manualBreakCount", manual.to_string()));
            }
        }
        let gone = |index: usize| {
            let mut at = Some(index);
            while let Some(node) = at {
                if removed.contains(&node) {
                    return true;
                }
                at = tree.nodes[node].parent;
            }
            false
        };
        let mut edits = Vec::new();
        for &index in &removed {
            if !tree.nodes[index].parent.is_some_and(gone) {
                edits.push((tree.nodes[index].span.clone(), Vec::new()));
            }
        }
        for (index, name, value) in sets {
            if !gone(index) {
                edits.push(set_attribute(&bytes, &tree.nodes[index], name, &value));
            }
        }
        for (index, name) in unsets {
            if !gone(index)
                && let Some(span) = tree.nodes[index].attr_spans.get(name)
            {
                let start = if span.start > 0 && bytes[span.start - 1].is_ascii_whitespace() {
                    span.start - 1
                } else {
                    span.start
                };
                edits.push((start..span.end, Vec::new()));
            }
        }
        for (index, text) in texts {
            if !gone(index) {
                edits.push((
                    tree.nodes[index].content.clone(),
                    escape_text(&text).into_bytes(),
                ));
            }
        }
        self.effects.extend(effects);
        if edits.is_empty() {
            return Ok(());
        }
        let value = splice(&bytes, edits).map_err(|_| refused("a part could not be rewritten"))?;
        self.package.replace_xml_part(part, value)?;
        Ok(())
    }
}
