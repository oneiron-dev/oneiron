//! Workbook cells, tables, styles, names and shared-string reads.
//! Entry: `read_xlsx_cells`.
//! Definitions live here; xlsx_body retains the old API and shared Book state.

use super::*;

/// Read every worksheet's cells, the defined names and the cell formats.
pub fn read_xlsx_cells(
    bytes: &[u8],
    limits: Limits,
    resources: &crate::resource::Resources,
) -> Result<XlsxBook> {
    let book = Book::open(bytes, limits, resources)?;
    let mut sheets = Vec::with_capacity(book.worksheets.len());
    for name in &book.order {
        if let Some(part) = book.worksheets.get(name) {
            // One parse serves the cells and the lines (FIX 9081).
            let tree = parse(&book.package, part)?;
            let (cells, locked, _) = book.sheet_in(part, &tree)?;
            let (rows, columns) = super::insert::sheet_lines(&tree)?;
            sheets.push(XlsxSheet {
                name: name.clone(),
                cells,
                locked,
                tables: book.tables(part)?,
                visibility: book.visibility.get(name).copied().unwrap_or_default(),
                rows,
                columns,
            });
        }
    }
    Ok(XlsxBook {
        date1904: book.date1904,
        sheets,
        names: book.names.clone(),
        styles: book.styles.clone(),
    })
}

impl Book {
    /// A worksheet's stored cells, its read-only ranges and its shared
    /// formula groups. A shared formula's anchor keeps its own text and each
    /// member reads the anchor's text moved to its cell, so both are
    /// writable; a member whose moved text would leave the sheet stays
    /// read-only.
    pub(super) fn sheet(&self, part: &str) -> Result<(Vec<XlsxCell>, Vec<XlsxArea>, SharedGroups)> {
        self.sheet_in(part, &parse(&self.package, part)?)
    }

    /// [`Self::sheet`] over worksheet `part` parsed as `tree`.
    fn sheet_in(
        &self,
        part: &str,
        tree: &XmlTree,
    ) -> Result<(Vec<XlsxCell>, Vec<XlsxArea>, SharedGroups)> {
        let mut cells = Vec::new();
        let mut areas = Vec::new();
        let mut seen = HashSet::new();
        // Each shared group's anchor (cell and text) by `si`, and every
        // shared cell by its index in `cells`, with whether it holds a rich
        // value.
        let mut anchors: HashMap<u32, ((u32, u32), String)> = HashMap::new();
        let mut sharing: Vec<(usize, u32, bool)> = Vec::new();
        let rows = match tree.child(0, SML, "sheetData")? {
            Some((data, _)) => tree
                .children(data)
                .filter(|(_, node)| node.is(SML, "row"))
                .map(|(index, _)| index)
                .collect(),
            None => Vec::new(),
        };
        for line in rows {
            for (index, node) in tree.children(line).filter(|(_, node)| node.is(SML, "c")) {
                let (col, row) = node
                    .attr("r")
                    .and_then(cell_ref)
                    .ok_or(refused("a worksheet cell has no reference"))?;
                if !seen.insert((col, row)) {
                    return Err(refused("a worksheet repeats a cell"));
                }
                let mut locked = None;
                let mut formula = None;
                let mut shared = None;
                if let Some((_, f)) = tree.child(index, SML, "f")? {
                    let text = (!f.text.trim().is_empty()).then(|| ui_form(&f.text));
                    let lock = match f.attr("t").unwrap_or("normal") {
                        "normal" if text.is_some() => None,
                        "normal" => Some(XlsxLock::Unsupported),
                        "shared" => Some(XlsxLock::SharedFormula),
                        "array" => Some(XlsxLock::ArrayFormula),
                        "dataTable" => Some(XlsxLock::DataTable),
                        _ => return Err(refused("an unknown formula kind")),
                    };
                    if let Some(lock @ (XlsxLock::ArrayFormula | XlsxLock::DataTable)) = lock {
                        let reference = f.attr("ref").unwrap_or(node.attr("r").unwrap_or(""));
                        areas.push(
                            XlsxArea::parse(reference, lock)
                                .ok_or(refused("an unreadable formula range"))?,
                        );
                    }
                    if lock == Some(XlsxLock::SharedFormula) {
                        shared = f.attr("si").and_then(|si| si.trim().parse::<u32>().ok());
                        // The anchor is the one cell naming the group's range.
                        if let (Some(si), Some(text), Some(_)) = (shared, &text, f.attr("ref")) {
                            anchors.insert(si, ((col, row), text.clone()));
                        }
                    }
                    formula = text;
                    locked = lock;
                }
                // A rich value's cell is read-only; a shared one still reads
                // its formula from its group first.
                let rich = node.attr("vm").is_some();
                if rich {
                    if shared.is_none() {
                        locked = Some(XlsxLock::RichValue);
                    }
                } else if node.attr("cm").is_some() {
                    locked.get_or_insert(XlsxLock::ArrayFormula);
                }
                let stored = tree
                    .child(index, SML, "v")?
                    .map(|(_, node)| node.text.clone());
                let value = match (node.attr("t").unwrap_or("n"), stored) {
                    ("inlineStr", _) => match tree.child(index, SML, "is")? {
                        Some((item, _)) => XlsxValue::Text(string_item(&tree, item)),
                        None => XlsxValue::Blank,
                    },
                    (_, None) => XlsxValue::Blank,
                    ("n", Some(value)) => XlsxValue::Number(
                        value
                            .trim()
                            .parse()
                            .map_err(|_| refused("an unreadable number cell"))?,
                    ),
                    ("s", Some(at)) => XlsxValue::Text(
                        at.trim()
                            .parse::<usize>()
                            .ok()
                            .and_then(|at| self.shared.get(at))
                            .ok_or(refused("a dangling shared string"))?
                            .clone(),
                    ),
                    ("str", Some(value)) => XlsxValue::Text(value),
                    ("b", Some(value)) => XlsxValue::Bool(truthy(&value)),
                    ("e", Some(value)) => XlsxValue::Error(value.trim().to_owned()),
                    ("d", Some(value)) => {
                        locked.get_or_insert(XlsxLock::Unsupported);
                        XlsxValue::Text(value)
                    }
                    _ => return Err(refused("an unknown cell type")),
                };
                let style = node
                    .attr("s")
                    .map(|style| {
                        style
                            .trim()
                            .parse::<u32>()
                            .map_err(|_| refused("an unreadable cell format"))
                    })
                    .transpose()?;
                if let Some(si) = shared {
                    sharing.push((cells.len(), si, rich));
                }
                cells.push(XlsxCell {
                    col,
                    row,
                    value,
                    formula,
                    style,
                    locked,
                });
            }
        }
        let mut groups = SharedGroups::new();
        for (index, si, rich) in sharing {
            let cell = &mut cells[index];
            let Some(((col, row), text)) = anchors.get(&si) else {
                continue;
            };
            let group = groups.entry(si).or_insert_with(|| SharedGroup {
                anchor: (*col, *row),
                cells: Vec::new(),
                complete: true,
            });
            group.cells.push((cell.col, cell.row));
            if cell.locked != Some(XlsxLock::SharedFormula) {
                group.complete = false;
                continue;
            }
            let own = if (cell.col, cell.row) == (*col, *row) {
                Some(text.clone())
            } else {
                shift_formula(
                    text,
                    i64::from(cell.row) - i64::from(*row),
                    i64::from(cell.col) - i64::from(*col),
                )
            };
            match own {
                Some(own) => {
                    cell.formula = Some(own);
                    cell.locked = rich.then_some(XlsxLock::RichValue);
                }
                None => group.complete = false,
            }
        }
        for table in self.tables(part)? {
            let range = XlsxArea {
                first: table.first,
                last: table.last,
                lock: XlsxLock::TableRow,
            };
            let (header, totals) = (table.header_rows, table.totals_rows);
            if header > 0 {
                areas.push(XlsxArea {
                    last: (range.last.0, (range.first.1 + header - 1).min(range.last.1)),
                    ..range
                });
            }
            if totals > 0 {
                areas.push(XlsxArea {
                    first: (
                        range.first.0,
                        (range.last.1 + 1).saturating_sub(totals).max(range.first.1),
                    ),
                    ..range
                });
            }
        }
        for cell in &mut cells {
            if cell.locked.is_none() {
                cell.locked = areas
                    .iter()
                    .find(|area| area.contains(cell.col, cell.row))
                    .map(|area| area.lock);
            }
        }
        Ok((cells, areas, groups))
    }

    /// A worksheet's tables.
    pub(super) fn tables(&self, part: &str) -> Result<Vec<XlsxTable>> {
        let mut tables = Vec::new();
        for rel in self
            .package
            .relationships(part)?
            .iter()
            .filter(|rel| !rel.external && rel.kind.ends_with("/table"))
        {
            let table = parse(&self.package, &rel.target)?;
            table
                .root(SML, "table")
                .map_err(|_| refused("an unreadable table part"))?;
            let node = &table.nodes[0];
            let range = node
                .attr("ref")
                .and_then(|reference| XlsxArea::parse(reference, XlsxLock::TableRow))
                .ok_or(refused("a table has no range"))?;
            let count = |name: &str, default: u32| {
                node.attr(name)
                    .and_then(|count| count.trim().parse::<u32>().ok())
                    .unwrap_or(default)
            };
            let mut columns = Vec::new();
            let mut calculated = Vec::new();
            if let Some((list, _)) = table.child(0, SML, "tableColumns")? {
                for (at, column) in table
                    .children(list)
                    .filter(|(_, node)| node.is(SML, "tableColumn"))
                {
                    columns.push(decode_escapes(column.attr("name").unwrap_or_default()));
                    calculated.push(
                        table
                            .children(at)
                            .find(|(_, node)| node.is(SML, "calculatedColumnFormula"))
                            .filter(|(_, formula)| {
                                !formula.attr("array").is_some_and(truthy)
                                    && !formula.text.trim().is_empty()
                            })
                            .map(|(_, formula)| ui_form(&formula.text)),
                    );
                }
            }
            if calculated.iter().all(Option::is_none) {
                calculated.clear();
            }
            tables.push(XlsxTable {
                name: node
                    .attr("displayName")
                    .or_else(|| node.attr("name"))
                    .unwrap_or_default()
                    .to_owned(),
                first: range.first,
                last: range.last,
                header_rows: count("headerRowCount", 1),
                totals_rows: count("totalsRowCount", 0),
                columns,
                worksheet: node
                    .attr("tableType")
                    .is_none_or(|kind| kind == "worksheet"),
                calculated,
            });
        }
        Ok(tables)
    }
}

pub(super) fn styles(tree: &XmlTree) -> Result<Vec<XlsxStyle>> {
    let mut codes = BTreeMap::new();
    if let Some((list, _)) = tree.child(0, SML, "numFmts")? {
        for (_, format) in tree
            .children(list)
            .filter(|(_, node)| node.is(SML, "numFmt"))
        {
            if let (Some(id), Some(code)) = (
                format
                    .attr("numFmtId")
                    .and_then(|id| id.trim().parse::<u32>().ok()),
                format.attr("formatCode"),
            ) {
                codes.insert(id, code.to_owned());
            }
        }
    }
    let Some((list, _)) = tree.child(0, SML, "cellXfs")? else {
        return Ok(Vec::new());
    };
    Ok(tree
        .children(list)
        .filter(|(_, node)| node.is(SML, "xf"))
        .map(|(_, xf)| {
            let num_fmt = xf
                .attr("numFmtId")
                .and_then(|id| id.trim().parse().ok())
                .unwrap_or(0);
            XlsxStyle {
                num_fmt,
                format: codes.get(&num_fmt).cloned(),
            }
        })
        .collect())
}

pub(super) fn names(tree: &XmlTree, order: &[String]) -> Result<Vec<XlsxName>> {
    let Some((list, _)) = tree.child(0, SML, "definedNames")? else {
        return Ok(Vec::new());
    };
    tree.children(list)
        .filter(|(_, node)| node.is(SML, "definedName"))
        .map(|(_, node)| {
            let name = node
                .attr("name")
                .ok_or(refused("a defined name has no name"))?;
            let sheet = match node.attr("localSheetId") {
                Some(at) => Some(
                    at.trim()
                        .parse::<usize>()
                        .ok()
                        .and_then(|at| order.get(at))
                        .ok_or(refused("a defined name's sheet does not exist"))?
                        .clone(),
                ),
                None => None,
            };
            let code = ["function", "vbProcedure", "xlm"]
                .iter()
                .any(|flag| node.attr(flag).is_some_and(truthy));
            Ok(XlsxName {
                name: name.to_owned(),
                sheet,
                formula: ui_form(&node.text),
                hidden: node.attr("hidden").is_some_and(truthy),
                locked: if name.to_ascii_lowercase().starts_with("_xlnm.") {
                    Some(XlsxLock::BuiltinName)
                } else if code {
                    Some(XlsxLock::Unsupported)
                } else {
                    None
                },
            })
        })
        .collect()
}

/// The text of a shared or inline string item, phonetic runs excluded, with
/// Excel's `_xHHHH_` escapes decoded.
pub(super) fn string_item(tree: &XmlTree, item: usize) -> String {
    fn raw(tree: &XmlTree, item: usize, out: &mut String) {
        for (index, node) in tree.children(item) {
            if node.is(SML, "t") {
                out.push_str(&node.text);
            } else if node.is(SML, "r") {
                raw(tree, index, out);
            }
        }
    }
    let mut out = String::new();
    raw(tree, item, &mut out);
    decode_escapes(&out)
}

pub(super) fn decode_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("_x") {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        match escape_at(tail) {
            Some(decoded) => {
                out.push(decoded);
                rest = &tail[7..];
            }
            None => {
                out.push('_');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}
