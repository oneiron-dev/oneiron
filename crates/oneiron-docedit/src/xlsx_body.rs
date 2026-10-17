//! The XLSX face of a live office body (ARCH-0075: "XLSX is a map keyed by
//! sheet and address"). A read feeds the import: each worksheet's cells with
//! their values, formulas and formats, the defined names and the workbook's
//! cell formats. The projection writes a body's changes into the imported
//! package, rebuilding only the rows and names it touches, and writes every
//! formula without a cached value; the engine then recalculates the package,
//! or [`mark_full_calc`] has the opening application do it. The body itself
//! (its Loro document, actors and forks) lives in the engine; this module
//! knows only SpreadsheetML.

use crate::ooxml::{
    DOCUMENT_RELATIONSHIPS as REL, SPREADSHEET_MAIN as SML, XmlError, XmlTree, escape_text,
};
use crate::retained_opc::{self, Limits, Package};
use crate::xlfn::{storage_form, ui_form};
use crate::xlsx_shift::shift_formula;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Excel's ceiling on one cell's text.
pub const MAX_TEXT_CHARS: usize = 32_767;
/// Excel's ceiling on one formula.
pub const MAX_FORMULA_CHARS: usize = 8_192;
const MAX_COLUMN: u32 = 16_384;
const MAX_ROW: u32 = 1_048_576;
/// The error values a cell may be written with.
const ERRORS: &[&str] = &[
    "#NULL!",
    "#DIV/0!",
    "#VALUE!",
    "#REF!",
    "#NAME?",
    "#NUM!",
    "#N/A",
    "#GETTING_DATA",
];

/// A workbook as the body imports it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct XlsxBook {
    /// Serial days count from 1904-01-01 rather than 1900-01-01.
    pub date1904: bool,
    /// Worksheets in workbook order; chart and dialog sheets hold no cells.
    pub sheets: Vec<XlsxSheet>,
    pub names: Vec<XlsxName>,
    /// The workbook's cell formats (`cellXfs`), by index.
    pub styles: Vec<XlsxStyle>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct XlsxSheet {
    pub name: String,
    /// Stored cells in row-major order.
    pub cells: Vec<XlsxCell>,
    /// Ranges the body may not write, stored cell or not: array formula and
    /// data table ranges, and table header and totals rows.
    pub locked: Vec<XlsxArea>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct XlsxCell {
    pub col: u32,
    pub row: u32,
    /// The stored value; a formula's is its cached result.
    pub value: XlsxValue,
    /// The formula as a person types it, without `=` or storage prefixes.
    pub formula: Option<String>,
    /// The cell format, an index into [`XlsxBook::styles`].
    pub style: Option<u32>,
    /// Why the body may not write this cell.
    pub locked: Option<XlsxLock>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XlsxValue {
    Blank,
    Number(f64),
    Text(String),
    Bool(bool),
    /// An error value such as `#N/A`.
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XlsxLock {
    /// A shared formula member whose anchor's text, moved to its cell, would
    /// leave the sheet, or one of a group with no anchor. Readable members
    /// carry their own text and are writable.
    SharedFormula,
    /// Inside an array formula's range, a dynamic array's spill included.
    ArrayFormula,
    /// Inside a what-if data table.
    DataTable,
    /// A rich value: an image in a cell, a linked data type.
    RichValue,
    /// A table's header or totals row, which the table part also names.
    TableRow,
    /// A value or name the body does not model: an ISO date cell, a macro name.
    Unsupported,
    /// A built-in name: a print area, a filter range.
    BuiltinName,
}

/// One shared formula group of a worksheet: its anchor, whose text the
/// members are written from, and every cell in it. `complete` when every
/// member's own text could be read, so the group can be written out cell by
/// cell.
struct SharedGroup {
    anchor: (u32, u32),
    cells: Vec<(u32, u32)>,
    complete: bool,
}

/// A worksheet's shared formula groups by `si`.
type SharedGroups = BTreeMap<u32, SharedGroup>;

/// A rectangular range, 1-based `(column, row)` corners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct XlsxArea {
    pub first: (u32, u32),
    pub last: (u32, u32),
    pub lock: XlsxLock,
}

impl XlsxArea {
    /// `B2:D9`, `$B$2`, or one cell.
    #[must_use]
    pub fn parse(reference: &str, lock: XlsxLock) -> Option<Self> {
        let (first, last) = reference.split_once(':').unwrap_or((reference, reference));
        let (first, last) = (cell_ref(first.trim())?, cell_ref(last.trim())?);
        Some(Self {
            first: (first.0.min(last.0), first.1.min(last.1)),
            last: (first.0.max(last.0), first.1.max(last.1)),
            lock,
        })
    }

    #[must_use]
    pub fn contains(&self, col: u32, row: u32) -> bool {
        (self.first.0..=self.last.0).contains(&col) && (self.first.1..=self.last.1).contains(&row)
    }

    #[must_use]
    pub fn reference(&self) -> String {
        let first = a1(self.first.0, self.first.1);
        if self.first == self.last {
            return first;
        }
        format!("{first}:{}", a1(self.last.0, self.last.1))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct XlsxName {
    pub name: String,
    /// The sheet a local name belongs to; `None` for a workbook name.
    pub sheet: Option<String>,
    /// What the name refers to, as a person types it.
    pub formula: String,
    pub hidden: bool,
    pub locked: Option<XlsxLock>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct XlsxStyle {
    pub num_fmt: u32,
    /// The workbook's own format code; a built-in format id has none.
    pub format: Option<String>,
}

/// One change a body makes to its imported workbook.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum XlsxChange {
    /// The cell's whole new state: a formula is written without a cached
    /// value; a blank cell without a format is removed.
    Cell {
        sheet: String,
        col: u32,
        row: u32,
        value: XlsxValue,
        formula: Option<String>,
        style: Option<u32>,
    },
    /// Add or replace a defined name.
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

#[derive(Debug, thiserror::Error)]
pub enum XlsxBodyError {
    #[error(transparent)]
    Package(#[from] retained_opc::Error),
    #[error(transparent)]
    Xml(#[from] XmlError),
    #[error("XLSX body refused: {0}")]
    Refused(&'static str),
}

type Result<T> = std::result::Result<T, XlsxBodyError>;

/// Read every worksheet's cells, the defined names and the cell formats.
pub fn read_xlsx_cells(bytes: &[u8], limits: Limits) -> Result<XlsxBook> {
    let book = Book::open(bytes, limits)?;
    let mut sheets = Vec::with_capacity(book.worksheets.len());
    for name in &book.order {
        if let Some(part) = book.worksheets.get(name) {
            let (cells, locked, _) = book.sheet(part)?;
            sheets.push(XlsxSheet {
                name: name.clone(),
                cells,
                locked,
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

/// Write `changes` into the imported package. Only the rows and names they
/// touch are rebuilt; every other byte of the package is kept. A change to a
/// read-only cell or name refuses. When a formula is removed the workbook's
/// calculation chain is dropped, since it would name a cell with no formula;
/// the opening application rebuilds it.
pub fn project_xlsx(source: &[u8], changes: &[XlsxChange], limits: Limits) -> Result<Vec<u8>> {
    if changes.is_empty() {
        return Ok(source.to_vec());
    }
    let mut book = Book::open(source, limits)?;
    let unshared = unshare_written_anchors(&book, changes)?;
    let mut by_sheet: BTreeMap<&str, BTreeMap<u32, BTreeMap<u32, &XlsxChange>>> = BTreeMap::new();
    let mut names = Vec::new();
    for change in changes.iter().chain(&unshared) {
        let XlsxChange::Cell {
            sheet,
            col,
            row,
            value,
            formula,
            style,
        } = change
        else {
            names.push(change);
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
        for (row, line) in rows {
            for (col, change) in line {
                let held = stored.get(&(*col, *row));
                if held.is_some_and(|cell| cell.locked.is_some())
                    || areas.iter().any(|area| area.contains(*col, *row))
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
            }
        }
        let bytes = rewrite_rows(&book.package, &part, rows)?;
        book.package.replace_xml_part(&part, bytes)?;
    }
    if !names.is_empty() {
        book.rewrite_names(&names)?;
    }
    if dropped_formula
        && let Some(chain) = book
            .package
            .relationships(&book.part)?
            .into_iter()
            .find(|rel| !rel.external && rel.kind.ends_with("/calcChain"))
    {
        book.package.unrelate(&book.part, &chain.id)?;
    }
    Ok(book.package.export()?)
}

/// The cells a write to a shared formula's anchor must also write: every
/// other member of its group not already written, as its own formula with
/// its format kept. The anchor holds the group's only text, so once it is
/// rewritten the members carry theirs. A group with a member whose text
/// could not be read refuses.
fn unshare_written_anchors(book: &Book, changes: &[XlsxChange]) -> Result<Vec<XlsxChange>> {
    let mut written: BTreeMap<&str, HashSet<(u32, u32)>> = BTreeMap::new();
    for change in changes {
        if let XlsxChange::Cell {
            sheet, col, row, ..
        } = change
        {
            written
                .entry(sheet.as_str())
                .or_default()
                .insert((*col, *row));
        }
    }
    let mut out = Vec::new();
    for (sheet, cells_written) in &written {
        let Some(part) = book.worksheets.get(*sheet) else {
            continue;
        };
        let (cells, _, groups) = book.sheet(part)?;
        let stored: HashMap<(u32, u32), &XlsxCell> = cells
            .iter()
            .map(|cell| ((cell.col, cell.row), cell))
            .collect();
        for group in groups.values() {
            if !cells_written.contains(&group.anchor) {
                continue;
            }
            if !group.complete {
                return Err(refused(
                    "a shared formula's anchor whose members cannot all be written out",
                ));
            }
            for at in &group.cells {
                if *at == group.anchor || cells_written.contains(at) {
                    continue;
                }
                let cell = stored
                    .get(at)
                    .ok_or(refused("a shared formula member is missing"))?;
                out.push(XlsxChange::Cell {
                    sheet: (*sheet).to_owned(),
                    col: at.0,
                    row: at.1,
                    value: cell.value.clone(),
                    formula: cell.formula.clone(),
                    style: cell.style,
                });
            }
        }
    }
    Ok(out)
}

/// Have the opening application recalculate every formula on load: the
/// projection's fallback when the engine cannot recalculate the workbook.
pub fn mark_full_calc(bytes: &[u8], limits: Limits) -> Result<Vec<u8>> {
    let mut book = Book::open(bytes, limits)?;
    let source = book
        .package
        .part(&book.part)?
        .ok_or(refused("the workbook part is missing"))?;
    let tree = XmlTree::parse(&source, limits.xml)?;
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

/// Refuse a value or formula Excel cannot hold. A formula is passed without
/// its leading `=`.
pub fn check_cell(value: &XlsxValue, formula: Option<&str>) -> Result<()> {
    if formula.is_some_and(|formula| {
        formula.trim().is_empty()
            || formula.starts_with('=')
            || formula.chars().count() > MAX_FORMULA_CHARS
    }) {
        return Err(refused(
            "a formula is 1 to 8,192 characters, without its `=`",
        ));
    }
    match value {
        XlsxValue::Number(number) if !number.is_finite() => Err(refused("a number must be finite")),
        XlsxValue::Text(text) if text.chars().count() > MAX_TEXT_CHARS => {
            Err(refused("a cell holds at most 32,767 characters"))
        }
        XlsxValue::Error(error) if !ERRORS.contains(&error.as_str()) => {
            Err(refused("an unknown error value"))
        }
        _ => Ok(()),
    }
}

/// Refuse a defined name Excel would not accept or that only Excel writes.
pub fn check_name(name: &str) -> Result<()> {
    let upper = name.to_ascii_uppercase();
    let valid = name
        .chars()
        .next()
        .is_some_and(|first| first.is_alphabetic() || matches!(first, '_' | '\\'))
        && name.chars().count() <= 255
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '\\'))
        && !upper.starts_with("_XLNM.")
        && cell_ref(&upper).is_none()
        && !matches!(upper.as_str(), "R" | "C");
    if !valid {
        return Err(refused("not a valid defined name"));
    }
    Ok(())
}

/// `B12` → `(2, 12)`; `$` anchors and lower case are accepted.
#[must_use]
pub fn parse_a1(text: &str) -> Option<(u32, u32)> {
    cell_ref(&text.trim().to_ascii_uppercase())
}

#[must_use]
pub fn a1(col: u32, row: u32) -> String {
    let mut letters = Vec::new();
    let mut col = col;
    while col > 0 {
        letters.push(b'A' + ((col - 1) % 26) as u8);
        col = (col - 1) / 26;
    }
    letters.reverse();
    format!("{}{row}", String::from_utf8(letters).unwrap_or_default())
}

/// An opened workbook package.
struct Book {
    package: Package,
    /// The workbook part.
    part: String,
    /// Every sheet's name in workbook order, which `localSheetId` indexes.
    order: Vec<String>,
    /// Worksheet name → part.
    worksheets: BTreeMap<String, String>,
    shared: Vec<String>,
    date1904: bool,
    names: Vec<XlsxName>,
    styles: Vec<XlsxStyle>,
}

impl Book {
    fn open(bytes: &[u8], limits: Limits) -> Result<Self> {
        let package = Package::open(bytes, limits)?;
        let part = package
            .relationships("")?
            .into_iter()
            .find(|rel| !rel.external && rel.kind.ends_with("/officeDocument"))
            .ok_or(refused("the package holds no workbook"))?
            .target;
        let tree = parse(&package, &part)?;
        tree.root(SML, "workbook")
            .map_err(|_| refused("the package holds no workbook"))?;
        let date1904 = tree
            .child(0, SML, "workbookPr")?
            .and_then(|(_, node)| node.attr("date1904"))
            .is_some_and(truthy);
        let links = package.relationships(&part)?;
        let mut order = Vec::new();
        let mut worksheets = BTreeMap::new();
        if let Some((list, _)) = tree.child(0, SML, "sheets")? {
            for (_, sheet) in tree
                .children(list)
                .filter(|(_, node)| node.is(SML, "sheet"))
            {
                let name = sheet.attr("name").ok_or(refused("a sheet has no name"))?;
                order.push(name.to_owned());
                if let Some(rel) = sheet.attr_ns(REL, "id").and_then(|id| {
                    links.iter().find(|rel| {
                        rel.id == id && !rel.external && rel.kind.ends_with("/worksheet")
                    })
                }) {
                    worksheets.insert(name.to_owned(), rel.target.clone());
                }
            }
        }
        let mut shared = Vec::new();
        if let Some(rel) = links
            .iter()
            .find(|rel| !rel.external && rel.kind.ends_with("/sharedStrings"))
        {
            let sst = parse(&package, &rel.target)?;
            for (item, _) in sst.children(0).filter(|(_, node)| node.is(SML, "si")) {
                shared.push(string_item(&sst, item));
            }
        }
        let styles = match links
            .iter()
            .find(|rel| !rel.external && rel.kind.ends_with("/styles"))
        {
            Some(rel) => styles(&parse(&package, &rel.target)?)?,
            None => Vec::new(),
        };
        let names = names(&tree, &order)?;
        Ok(Self {
            package,
            part,
            order,
            worksheets,
            shared,
            date1904,
            names,
            styles,
        })
    }

    /// A worksheet's stored cells, its read-only ranges and its shared
    /// formula groups. A shared formula's anchor keeps its own text and each
    /// member reads the anchor's text moved to its cell, so both are
    /// writable; a member whose moved text would leave the sheet stays
    /// read-only.
    fn sheet(&self, part: &str) -> Result<(Vec<XlsxCell>, Vec<XlsxArea>, SharedGroups)> {
        let tree = parse(&self.package, part)?;
        let mut cells = Vec::new();
        let mut areas = Vec::new();
        let mut seen = HashSet::new();
        // Each shared group's anchor (cell and text) by `si`, and every
        // shared cell by its index in `cells`.
        let mut anchors: HashMap<u32, ((u32, u32), String)> = HashMap::new();
        let mut sharing: Vec<(usize, u32)> = Vec::new();
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
                if node.attr("vm").is_some() {
                    locked = Some(XlsxLock::RichValue);
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
                    sharing.push((cells.len(), si));
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
        for (index, si) in sharing {
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
                    cell.locked = None;
                }
                None => group.complete = false,
            }
        }
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
            let (header, totals) = (count("headerRowCount", 1), count("totalsRowCount", 0));
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

    /// Rebuild `definedNames` with the changed names replaced, added or
    /// removed; untouched names keep their bytes.
    fn rewrite_names(&mut self, changes: &[&XlsxChange]) -> Result<()> {
        let bytes = self
            .package
            .part(&self.part)?
            .ok_or(refused("the workbook part is missing"))?;
        let tree = XmlTree::parse(&bytes, self.package.limits().xml)?;
        let root = &tree.nodes[0];
        let element = root.child_name("definedName");
        let mut pending: Vec<((String, Option<usize>), Option<String>)> = Vec::new();
        for change in changes {
            let (name, sheet, xml) = match change {
                XlsxChange::SetName {
                    name,
                    sheet,
                    formula,
                    hidden,
                } => {
                    check_name(name)?;
                    check_cell(&XlsxValue::Blank, Some(formula))?;
                    let local = local_sheet(&self.order, sheet.as_deref())?
                        .map_or_else(String::new, |at| format!(" localSheetId=\"{at}\""));
                    let hidden = if *hidden { " hidden=\"1\"" } else { "" };
                    let xml = format!(
                        "<{element} name=\"{}\"{local}{hidden}>{}</{element}>",
                        escape_text(name),
                        escape_text(&storage_form(formula)),
                    );
                    (name, sheet, Some(xml))
                }
                XlsxChange::DeleteName { name, sheet } => (name, sheet, None),
                XlsxChange::Cell { .. } => continue,
            };
            let key = (
                name.to_lowercase(),
                local_sheet(&self.order, sheet.as_deref())?,
            );
            if pending.iter().any(|(held, _)| *held == key) {
                return Err(refused("two changes write one name"));
            }
            pending.push((key, xml));
        }
        let list = tree.child(0, SML, "definedNames")?;
        let mut children = Vec::new();
        if let Some((list, _)) = list {
            for (_, node) in tree
                .children(list)
                .filter(|(_, node)| node.is(SML, "definedName"))
            {
                let name = node.attr("name").unwrap_or_default().to_lowercase();
                let local = node
                    .attr("localSheetId")
                    .and_then(|at| at.trim().parse::<usize>().ok());
                match pending
                    .iter()
                    .position(|(key, _)| key.0 == name && key.1 == local)
                {
                    Some(at) => {
                        if name.starts_with("_xlnm.") {
                            return Err(refused("a built-in name is read-only"));
                        }
                        if let (_, Some(xml)) = pending.remove(at) {
                            children.extend_from_slice(xml.as_bytes());
                        }
                    }
                    None => children.extend_from_slice(&bytes[node.span.clone()]),
                }
            }
        }
        for (_, xml) in pending {
            children.extend(xml.ok_or(refused("no such defined name"))?.into_bytes());
        }
        let wrapper = root.child_name("definedNames");
        let replacement = if children.is_empty() {
            Vec::new()
        } else {
            [
                format!("<{wrapper}>").into_bytes(),
                children,
                format!("</{wrapper}>").into_bytes(),
            ]
            .concat()
        };
        let value = match list {
            Some((_, node)) => [
                &bytes[..node.span.start],
                &replacement[..],
                &bytes[node.span.end..],
            ]
            .concat(),
            None => {
                let at = insertion(&tree, &["sheets", "functionGroups", "externalReferences"])
                    .ok_or(refused("the workbook has no sheet list"))?;
                [&bytes[..at], &replacement[..], &bytes[at..]].concat()
            }
        };
        self.package.replace_xml_part(&self.part, value)?;
        Ok(())
    }
}

/// Rebuild `sheetData` with the touched rows rewritten in column order and new
/// rows inserted in row order; untouched rows and cells keep their bytes.
fn rewrite_rows(
    package: &Package,
    part: &str,
    rows: &BTreeMap<u32, BTreeMap<u32, &XlsxChange>>,
) -> Result<Vec<u8>> {
    let bytes = package
        .part(part)?
        .ok_or(refused("a worksheet part is missing"))?;
    let tree = XmlTree::parse(&bytes, package.limits().xml)?;
    let (data, data_node) = tree
        .child(0, SML, "sheetData")?
        .ok_or(refused("a worksheet has no sheetData"))?;
    let mut pending: BTreeMap<u32, &BTreeMap<u32, &XlsxChange>> =
        rows.iter().map(|(row, line)| (*row, line)).collect();
    let mut out_rows: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    for (index, row) in tree.children(data).filter(|(_, node)| node.is(SML, "row")) {
        let number = row
            .attr("r")
            .and_then(|r| r.trim().parse::<u32>().ok())
            .ok_or(refused("a worksheet row has no number"))?;
        if out_rows.contains_key(&number) {
            return Err(refused("a worksheet repeats a row"));
        }
        let Some(changes) = pending.remove(&number) else {
            out_rows.insert(number, bytes[row.span.clone()].to_vec());
            continue;
        };
        let mut line: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        for (_, cell) in tree.children(index).filter(|(_, node)| node.is(SML, "c")) {
            let col = cell
                .attr("r")
                .and_then(cell_ref)
                .ok_or(refused("a worksheet cell has no reference"))?
                .0;
            line.insert(col, bytes[cell.span.clone()].to_vec());
        }
        let cell_name = row.child_name("c");
        for (col, change) in changes {
            match cell_xml(&cell_name, *col, number, change)? {
                Some(cell) => line.insert(*col, cell.into_bytes()),
                None => line.remove(col),
            };
        }
        let open = &bytes[row.span.start..row.open_end];
        let open = if row.empty {
            open.strip_suffix(b"/>").unwrap_or(open)
        } else {
            open.strip_suffix(b">").unwrap_or(open)
        };
        let mut out = open.to_vec();
        out.push(b'>');
        line.into_values().for_each(|cell| out.extend(cell));
        out.extend_from_slice(format!("</{}>", row.qualified).as_bytes());
        out_rows.insert(number, out);
    }
    let row_name = data_node.child_name("row");
    let cell_name = data_node.child_name("c");
    for (number, changes) in pending {
        let mut cells = String::new();
        for (col, change) in changes {
            if let Some(cell) = cell_xml(&cell_name, *col, number, change)? {
                cells.push_str(&cell);
            }
        }
        if !cells.is_empty() {
            out_rows.insert(
                number,
                format!("<{row_name} r=\"{number}\">{cells}</{row_name}>").into_bytes(),
            );
        }
    }
    let open = &bytes[data_node.span.start..data_node.open_end];
    let open = open
        .strip_suffix(b"/>")
        .or_else(|| open.strip_suffix(b">"))
        .unwrap_or(open);
    let mut out = bytes[..data_node.span.start].to_vec();
    out.extend_from_slice(open);
    out.push(b'>');
    out_rows.into_values().for_each(|row| out.extend(row));
    out.extend_from_slice(format!("</{}>", data_node.qualified).as_bytes());
    out.extend_from_slice(&bytes[data_node.span.end..]);
    Ok(out)
}

/// One cell element as the body writes it; `None` removes a blank cell
/// without a format.
fn cell_xml(name: &str, col: u32, row: u32, change: &XlsxChange) -> Result<Option<String>> {
    let XlsxChange::Cell {
        value,
        formula,
        style,
        ..
    } = change
    else {
        return Err(refused("not a cell change"));
    };
    let prefix = name.strip_suffix('c').unwrap_or("");
    let r = a1(col, row);
    let s = style.map_or_else(String::new, |style| format!(" s=\"{style}\""));
    if let Some(formula) = formula {
        return Ok(Some(format!(
            "<{name} r=\"{r}\"{s}><{prefix}f>{}</{prefix}f></{name}>",
            escape_text(&storage_form(formula))
        )));
    }
    Ok(Some(match value {
        XlsxValue::Blank if style.is_none() => return Ok(None),
        XlsxValue::Blank => format!("<{name} r=\"{r}\"{s}/>"),
        XlsxValue::Number(number) => {
            format!("<{name} r=\"{r}\"{s}><{prefix}v>{number}</{prefix}v></{name}>")
        }
        XlsxValue::Text(text) => format!(
            "<{name} r=\"{r}\"{s} t=\"inlineStr\"><{prefix}is><{prefix}t xml:space=\"preserve\">{}</{prefix}t></{prefix}is></{name}>",
            escape_text(&encode_escapes(text))
        ),
        XlsxValue::Bool(flag) => format!(
            "<{name} r=\"{r}\"{s} t=\"b\"><{prefix}v>{}</{prefix}v></{name}>",
            u8::from(*flag)
        ),
        XlsxValue::Error(error) => format!(
            "<{name} r=\"{r}\"{s} t=\"e\"><{prefix}v>{}</{prefix}v></{name}>",
            escape_text(error)
        ),
    }))
}

fn styles(tree: &XmlTree) -> Result<Vec<XlsxStyle>> {
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

fn names(tree: &XmlTree, order: &[String]) -> Result<Vec<XlsxName>> {
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

fn local_sheet(order: &[String], sheet: Option<&str>) -> Result<Option<usize>> {
    sheet
        .map(|sheet| {
            order
                .iter()
                .position(|name| name == sheet)
                .ok_or(refused("a defined name's sheet does not exist"))
        })
        .transpose()
}

/// The byte offset just past the last of these workbook children present,
/// where a following child goes.
fn insertion(tree: &XmlTree, after: &[&str]) -> Option<usize> {
    tree.children(0)
        .filter(|(_, node)| node.namespace == SML && after.contains(&node.name.as_str()))
        .map(|(_, node)| node.span.end)
        .max()
}

fn parse(package: &Package, part: &str) -> Result<XmlTree> {
    let bytes = package
        .part(part)?
        .ok_or(refused("a workbook part is missing"))?;
    Ok(XmlTree::parse(&bytes, package.limits().xml)?)
}

/// `$B$12` → `(2, 12)`.
fn cell_ref(text: &str) -> Option<(u32, u32)> {
    let text = text.strip_prefix('$').unwrap_or(text);
    let split = text.find(|c: char| !c.is_ascii_uppercase())?;
    let (letters, digits) = text.split_at(split);
    let digits = digits.strip_prefix('$').unwrap_or(digits);
    if letters.is_empty() || letters.len() > 3 || digits.starts_with('0') {
        return None;
    }
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let col = letters
        .bytes()
        .fold(0u32, |sum, byte| sum * 26 + u32::from(byte - b'A' + 1));
    let row = digits.parse::<u32>().ok()?;
    (col <= MAX_COLUMN && (1..=MAX_ROW).contains(&row)).then_some((col, row))
}

/// The text of a shared or inline string item, phonetic runs excluded, with
/// Excel's `_xHHHH_` escapes decoded.
fn string_item(tree: &XmlTree, item: usize) -> String {
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

fn decode_escapes(text: &str) -> String {
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

/// A literal `_xHHHH_` escapes its underscore; a character XML cannot carry
/// becomes its own escape.
fn encode_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (at, c) in text.char_indices() {
        if c == '_' && escape_at(&text[at..]).is_some() {
            out.push_str("_x005F_");
        } else if matches!(
            c,
            '\u{0}'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{1f}' | '\u{fffe}' | '\u{ffff}'
        ) {
            out.push_str(&format!("_x{:04X}_", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// The character an `_xHHHH_` escape at the start of `text` stands for.
fn escape_at(text: &str) -> Option<char> {
    let bytes = text.as_bytes();
    if bytes.len() < 7 || !bytes.starts_with(b"_x") || bytes[6] != b'_' {
        return None;
    }
    if !bytes[2..6].iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    char::from_u32(u32::from_str_radix(&text[2..6], 16).ok()?)
}

fn truthy(value: &str) -> bool {
    matches!(value.trim(), "1" | "true")
}

fn refused(reason: &'static str) -> XlsxBodyError {
    XlsxBodyError::Refused(reason)
}
