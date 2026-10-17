//! The XLSX face of a live office body (ARCH-0075: "XLSX is a map keyed by
//! sheet and address"). A read feeds the import: each worksheet's cells with
//! their values, formulas and formats, the defined names and the workbook's
//! cell formats. The projection writes a body's changes into the imported
//! package, rebuilding only the rows and names it touches, and writes every
//! formula without a cached value; the engine then recalculates the package,
//! or [`mark_full_calc`] has the opening application do it. A sheet layout
//! change renames, moves, adds and deletes worksheets first, retargeting
//! every formula that names a renamed or deleted sheet; row and column inserts
//! and deletes come next, moving cells, ranges and every reference into the
//! sheet, and a deleted reference reads `#REF!`. The cell formats a body
//! composed go into the stylesheet before any cell names them. The body itself
//! (its Loro document, actors and forks) lives in the engine; this module
//! knows only SpreadsheetML.

use crate::edit::xml::{escape_attribute, next_part, set_attribute, splice};
use crate::ooxml::{
    DOCUMENT_RELATIONSHIPS as REL, Node, SPREADSHEET_MAIN as SML, XmlError, XmlTree, escape_text,
};
use crate::retained_opc::{self, Limits, Package};
use crate::xlfn::{storage_form, ui_form};
use crate::xlsx_shift::shift_formula;
pub use crate::xlsx_shift::{SheetFate, XlsxAxis, XlsxAxisEdit, retarget_sheets, shift_axis};
use crate::xlsx_styles::write_formats;
pub use crate::xlsx_styles::{
    XlsxBorder, XlsxColor, XlsxEdge, XlsxFill, XlsxFont, XlsxFormat, XlsxNumberFormat, check_format,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Excel's ceiling on one cell's text.
pub const MAX_TEXT_CHARS: usize = 32_767;
/// Excel's ceiling on one formula.
pub const MAX_FORMULA_CHARS: usize = 8_192;
const MAX_COLUMN: u32 = 16_384;
const MAX_ROW: u32 = 1_048_576;
/// Excel's ceiling on a sheet name.
const MAX_SHEET_NAME: usize = 31;
const WORKSHEET_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml";
const WORKSHEET_KIND: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet";
/// The elements whose text is a formula: cells, rules and validations,
/// chart ranges, table columns.
const FORMULA_ELEMENTS: &[&str] = &[
    "f",
    "formula",
    "formula1",
    "formula2",
    "calculatedColumnFormula",
    "totalsRowFormula",
];
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
    /// The worksheets after the body's sheet operations, in workbook order.
    /// An imported worksheet left out is deleted, and the formulas naming it
    /// read `#REF!`; a renamed one's formulas follow it. Written before every
    /// other change, which names sheets as listed here.
    Sheets {
        sheets: Vec<XlsxSheetPlan>,
    },
    /// Insert or delete rows or columns in a worksheet, named as the sheet
    /// layout leaves it. Written in order after the layout and before every
    /// cell and name, which are addressed as the edits leave the sheet.
    Shift {
        sheet: String,
        edit: XlsxAxisEdit,
    },
    /// Cell formats the body composed, written into the stylesheet before
    /// the cells: a cell's `style` of the workbook's format count plus `k`
    /// names the `k`-th. An equal record the stylesheet holds is reused.
    Formats {
        formats: Vec<XlsxFormat>,
    },
}

/// One worksheet of a sheet layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XlsxSheetPlan {
    pub name: String,
    /// The imported worksheet it is, by its imported name; `None` for a new,
    /// empty one.
    pub source: Option<String>,
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
/// read-only cell or name refuses. When a formula is removed, sheets are laid
/// out again or rows and columns move, the workbook's calculation chain is
/// dropped, since it would name the wrong cells; the opening application
/// rebuilds it.
pub fn project_xlsx(source: &[u8], changes: &[XlsxChange], limits: Limits) -> Result<Vec<u8>> {
    if changes.is_empty() {
        return Ok(source.to_vec());
    }
    let mut book = Book::open(source, limits)?;
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
            if !matches!(
                change,
                XlsxChange::Sheets { .. } | XlsxChange::Shift { .. } | XlsxChange::Formats { .. }
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

/// Refuse a worksheet name Excel would not accept: 1 to 31 characters, none
/// of `: \ / ? * [ ]`, no apostrophe at either end, and not `History`, which
/// Excel keeps for itself.
pub fn check_sheet_name(name: &str) -> Result<()> {
    let valid = (1..=MAX_SHEET_NAME).contains(&name.chars().count())
        && !name.contains(&[':', '\\', '/', '?', '*', '[', ']'][..])
        && !name.starts_with('\'')
        && !name.ends_with('\'')
        && !name.chars().any(char::is_control)
        && !name.eq_ignore_ascii_case("history");
    if !valid {
        return Err(refused("not a valid worksheet name"));
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
    /// The stylesheet part, when the workbook has one.
    styles_part: Option<String>,
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
        let styles_part = links
            .iter()
            .find(|rel| !rel.external && rel.kind.ends_with("/styles"))
            .map(|rel| rel.target.clone());
        let styles = match &styles_part {
            Some(part) => styles(&parse(&package, part)?)?,
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
            styles_part,
            styles,
        })
    }

    /// Write the body's cell formats into the stylesheet: each one's index in
    /// `cellXfs`, in order. The workbook's formats are read again after.
    fn resolve_formats(&mut self, formats: &[XlsxFormat]) -> Result<Vec<u32>> {
        let part = self.styles_part.clone().ok_or(refused(
            "the workbook has no stylesheet to add a cell format to",
        ))?;
        let bytes = self
            .package
            .part(&part)?
            .ok_or(refused("a workbook part is missing"))?;
        let (indices, value) = write_formats(
            &bytes,
            self.package.limits().xml,
            formats,
            self.styles.len(),
        )?;
        if let Some(value) = value {
            self.package.replace_xml_part(&part, value)?;
            self.styles = styles(&parse(&self.package, &part)?)?;
        }
        Ok(indices)
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

    /// Write a sheet layout: rename, reorder, add and delete worksheets in the
    /// sheet list; carry each defined name's scope and the workbook view's
    /// tabs to the new order, dropping names local to a deleted sheet; and
    /// retarget every formula, chart range and hyperlink that names a renamed
    /// or deleted sheet. A deleted sheet's parts leave with it unless another
    /// part still reaches them. A chart or dialog sheet stays after the
    /// worksheet it followed.
    fn relayout(&mut self, plan: &[XlsxSheetPlan]) -> Result<()> {
        let mut taken = HashSet::new();
        let mut kept = HashSet::new();
        for slot in plan {
            check_sheet_name(&slot.name)?;
            if !taken.insert(slot.name.to_lowercase()) {
                return Err(refused("two sheets share a name"));
            }
            if let Some(source) = &slot.source
                && (!self.worksheets.contains_key(source) || !kept.insert(source.as_str()))
            {
                return Err(refused(
                    "a sheet layout names an imported worksheet twice or not at all",
                ));
            }
        }
        if plan.is_empty() {
            return Err(refused("a workbook keeps at least one worksheet"));
        }
        if self
            .order
            .iter()
            .any(|name| !self.worksheets.contains_key(name) && taken.contains(&name.to_lowercase()))
        {
            return Err(refused("two sheets share a name"));
        }
        let bytes = self
            .package
            .part(&self.part)?
            .ok_or(refused("the workbook part is missing"))?;
        let tree = XmlTree::parse(&bytes, self.package.limits().xml)?;
        let (list, list_node) = tree
            .child(0, SML, "sheets")?
            .ok_or(refused("the workbook has no sheet list"))?;
        let entries: Vec<_> = tree
            .children(list)
            .filter(|(_, node)| node.is(SML, "sheet"))
            .map(|(_, node)| node)
            .collect();
        // The final order: (index in the old order, name), `None` for a new
        // worksheet.
        let mut layout: Vec<(Option<usize>, String)> = Vec::new();
        {
            let mut followers: HashMap<Option<&str>, Vec<usize>> = HashMap::new();
            let mut anchor = None;
            for (at, name) in self.order.iter().enumerate() {
                if !self.worksheets.contains_key(name) {
                    followers.entry(anchor).or_default().push(at);
                } else if kept.contains(name.as_str()) {
                    anchor = Some(name.as_str());
                }
            }
            for at in followers.remove(&None).unwrap_or_default() {
                layout.push((Some(at), self.order[at].clone()));
            }
            for slot in plan {
                let Some(source) = &slot.source else {
                    layout.push((None, slot.name.clone()));
                    continue;
                };
                let at = self
                    .order
                    .iter()
                    .position(|name| name == source)
                    .ok_or(refused("no such worksheet"))?;
                layout.push((Some(at), slot.name.clone()));
                for at in followers.remove(&Some(source.as_str())).unwrap_or_default() {
                    layout.push((Some(at), self.order[at].clone()));
                }
            }
        }
        let first_visible = layout
            .iter()
            .position(|(old, _)| {
                old.is_none_or(|at| {
                    !matches!(entries[at].attr("state"), Some("hidden" | "veryHidden"))
                })
            })
            .ok_or(refused("a workbook keeps one visible sheet"))?;
        let mut moved: Vec<Option<usize>> = vec![None; self.order.len()];
        for (new, (old, _)) in layout.iter().enumerate() {
            if let Some(old) = old {
                moved[*old] = Some(new);
            }
        }
        let mut fates: HashMap<String, SheetFate> = HashMap::new();
        let mut dropped = Vec::new();
        for (at, name) in self.order.iter().enumerate() {
            match moved[at] {
                None => {
                    fates.insert(name.to_lowercase(), SheetFate::Delete);
                    dropped.extend(entries[at].attr_ns(REL, "id").map(str::to_owned));
                }
                Some(new) if layout[new].1 != *name => {
                    fates.insert(
                        name.to_lowercase(),
                        SheetFate::Rename(layout[new].1.clone()),
                    );
                }
                Some(_) => {}
            }
        }
        let fate = |name: &str| {
            fates
                .get(&name.to_lowercase())
                .cloned()
                .unwrap_or(SheetFate::Keep)
        };
        // A new `<sheet>` names its part with the prefix the others use.
        let rel_attr = entries.iter().find_map(|node| {
            let id = node.attr_ns(REL, "id")?;
            node.attrs
                .iter()
                .find(|(name, value)| name.ends_with(":id") && value.as_str() == id)
                .map(|(name, _)| name.clone())
        });
        let sheet_element = entries.first().map_or_else(
            || list_node.child_name("sheet"),
            |node| node.qualified.clone(),
        );
        let mut sheet_id = entries
            .iter()
            .filter_map(|node| node.attr("sheetId")?.trim().parse::<u32>().ok())
            .max()
            .unwrap_or(0);
        let dir = self
            .worksheets
            .values()
            .find_map(|part| part.rsplit_once('/').map(|(dir, _)| dir.to_owned()))
            .unwrap_or_else(|| match self.part.rsplit_once('/') {
                Some((dir, _)) => format!("{dir}/worksheets"),
                None => "worksheets".to_owned(),
            });
        let kind = self
            .package
            .relationships(&self.part)?
            .into_iter()
            .find(|rel| !rel.external && rel.kind.ends_with("/worksheet"))
            .map_or_else(|| WORKSHEET_KIND.to_owned(), |rel| rel.kind);
        let mut content = Vec::new();
        let mut worksheets = BTreeMap::new();
        for (old, name) in &layout {
            let Some(at) = old else {
                let part = next_part(&self.package, &format!("{dir}/sheet"), ".xml")
                    .map_err(|_| refused("no free worksheet part name"))?;
                let seed = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<worksheet xmlns=\"{SML}\"><sheetData/></worksheet>"
                );
                self.package
                    .add_part(&part, WORKSHEET_TYPE, seed.into_bytes())?;
                let id = self.package.relate(&self.part, &kind, &part)?;
                sheet_id = sheet_id.checked_add(1).ok_or(refused("no free sheet id"))?;
                let link = rel_attr.as_ref().map_or_else(
                    || format!("xmlns:r=\"{REL}\" r:id=\"{id}\""),
                    |attr| format!("{attr}=\"{id}\""),
                );
                content.extend_from_slice(
                    format!(
                        "<{sheet_element} name=\"{}\" sheetId=\"{sheet_id}\" {link}/>",
                        escape_text(name)
                    )
                    .as_bytes(),
                );
                worksheets.insert(name.clone(), part);
                continue;
            };
            let node = entries[*at];
            if *name == self.order[*at] {
                content.extend_from_slice(&bytes[node.span.clone()]);
            } else {
                let attr = node
                    .attr_spans
                    .get("name")
                    .ok_or(refused("a sheet has no name"))?;
                content.extend_from_slice(&bytes[node.span.start..attr.start]);
                content.extend_from_slice(format!("name=\"{}\"", escape_text(name)).as_bytes());
                content.extend_from_slice(&bytes[attr.end..node.span.end]);
            }
            if let Some(part) = self.worksheets.get(&self.order[*at]) {
                worksheets.insert(name.clone(), part.clone());
            }
        }
        let mut edits = vec![(list_node.content.clone(), content)];
        if let Some((list, node)) = tree.child(0, SML, "definedNames")? {
            let mut kept_names = 0;
            let mut name_edits = Vec::new();
            for (_, name) in tree
                .children(list)
                .filter(|(_, node)| node.is(SML, "definedName"))
            {
                if let Some(old) = name
                    .attr("localSheetId")
                    .and_then(|at| at.trim().parse::<usize>().ok())
                {
                    match moved.get(old).copied().flatten() {
                        None => {
                            name_edits.push((name.span.clone(), Vec::new()));
                            continue;
                        }
                        Some(new) if new != old => name_edits.push(set_attribute(
                            &bytes,
                            name,
                            "localSheetId",
                            &new.to_string(),
                        )),
                        Some(_) => {}
                    }
                }
                kept_names += 1;
                if !name.empty
                    && let Some(text) = retarget_sheets(&name.text, &fate)
                {
                    name_edits.push((name.content.clone(), escape_text(&text).into_bytes()));
                }
            }
            if kept_names == 0 {
                edits.push((node.span.clone(), Vec::new()));
            } else {
                edits.extend(name_edits);
            }
        }
        if let Some((views, _)) = tree.child(0, SML, "bookViews")? {
            for (_, view) in tree
                .children(views)
                .filter(|(_, node)| node.is(SML, "workbookView"))
            {
                for attr in ["activeTab", "firstSheet"] {
                    let Some(old) = view
                        .attr(attr)
                        .and_then(|at| at.trim().parse::<usize>().ok())
                    else {
                        continue;
                    };
                    let new = moved.get(old).copied().flatten().unwrap_or(first_visible);
                    if new != old {
                        edits.push(set_attribute(&bytes, view, attr, &new.to_string()));
                    }
                }
            }
        }
        let value = splice(&bytes, edits)
            .map_err(|_| refused("the workbook part could not be rewritten"))?;
        self.package.replace_xml_part(&self.part, value)?;
        if !dropped.is_empty() {
            let before = self.package.reachable("")?;
            for id in &dropped {
                self.package.unrelate(&self.part, id)?;
            }
            let after = self.package.reachable("")?;
            for part in before.difference(&after) {
                if self.package.names().any(|name| name == part.as_str()) {
                    self.package.remove_part(part)?;
                }
            }
            self.package.prune_defaults()?;
        }
        if !fates.is_empty() {
            let parts: Vec<String> = self
                .package
                .names()
                .filter(|name| {
                    let lower = name.to_ascii_lowercase();
                    lower.ends_with(".xml")
                        && ["/worksheets/", "/charts/", "/tables/"]
                            .iter()
                            .any(|dir| lower.contains(dir))
                })
                .map(str::to_owned)
                .collect();
            for part in parts {
                self.rewrite_formulas(&part, &|text: &str| retarget_sheets(text, &fate))?;
            }
        }
        self.order = layout.into_iter().map(|(_, name)| name).collect();
        self.worksheets = worksheets;
        Ok(())
    }

    /// Rewrite one part's formulas (its defined names, for the workbook) and
    /// hyperlink locations through `rewrite`, which answers `None` for text
    /// it leaves alone.
    fn rewrite_formulas(
        &mut self,
        part: &str,
        rewrite: &dyn Fn(&str) -> Option<String>,
    ) -> Result<()> {
        let bytes = self
            .package
            .part(part)?
            .ok_or(refused("a workbook part is missing"))?;
        let tree = XmlTree::parse(&bytes, self.package.limits().xml)?;
        let mut edits = Vec::new();
        for node in &tree.nodes {
            if (FORMULA_ELEMENTS.contains(&node.name.as_str()) || node.is(SML, "definedName"))
                && node.children.is_empty()
                && !node.empty
            {
                if let Some(text) = rewrite(&node.text) {
                    edits.push((node.content.clone(), escape_text(&text).into_bytes()));
                }
            } else if node.is(SML, "hyperlink")
                && let Some(text) = node.attr("location").and_then(rewrite)
            {
                edits.push(set_attribute(&bytes, node, "location", &text));
            }
        }
        if edits.is_empty() {
            return Ok(());
        }
        let value = splice(&bytes, edits).map_err(|_| refused("a part could not be rewritten"))?;
        self.package.replace_xml_part(part, value)?;
        Ok(())
    }

    /// Write every shared formula out cell by cell, each member with its own
    /// text, so a row or column edit moves each cell's references alone. A
    /// group whose members cannot all be read refuses.
    fn unshare_all(&mut self) -> Result<()> {
        let parts: Vec<String> = self.worksheets.values().cloned().collect();
        for part in parts {
            let (cells, _, groups) = self.sheet(&part)?;
            if cells
                .iter()
                .any(|cell| cell.locked == Some(XlsxLock::SharedFormula))
                || groups.values().any(|group| !group.complete)
            {
                return Err(refused(
                    "a shared formula whose members cannot all be written out",
                ));
            }
            if groups.is_empty() {
                continue;
            }
            let own: HashMap<(u32, u32), &str> = cells
                .iter()
                .filter_map(|cell| Some(((cell.col, cell.row), cell.formula.as_deref()?)))
                .collect();
            let bytes = self
                .package
                .part(&part)?
                .ok_or(refused("a worksheet part is missing"))?;
            let tree = XmlTree::parse(&bytes, self.package.limits().xml)?;
            let mut edits = Vec::new();
            for node in &tree.nodes {
                if !node.is(SML, "f") || node.attr("t") != Some("shared") {
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
                edits.push((
                    node.span.clone(),
                    format!(
                        "<{0}>{1}</{0}>",
                        node.qualified,
                        escape_text(&storage_form(text))
                    )
                    .into_bytes(),
                ));
            }
            let value =
                splice(&bytes, edits).map_err(|_| refused("a worksheet could not be rewritten"))?;
            self.package.replace_xml_part(&part, value)?;
        }
        Ok(())
    }

    /// Insert or delete rows or columns in one worksheet, as Excel does. Its
    /// rows and cells, merged ranges, conditional formats, validations,
    /// hyperlinks, filters, column widths, tables and comments move; what the
    /// edit deletes goes, and a range that loses part of itself shrinks. A
    /// table gains or loses the columns inserted or deleted inside it. Then
    /// every formula, chart range, hyperlink location and defined name that
    /// reaches the sheet follows, a reference to a deleted cell reading
    /// `#REF!`. Shared formulas must be written out first.
    fn shift(&mut self, sheet: &str, edit: &XlsxAxisEdit) -> Result<()> {
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
        for rel in self.package.relationships(&part)? {
            if rel.external {
                continue;
            }
            if rel.kind.ends_with("/table") {
                tables.push(rel.target.clone());
            }
            if ["/table", "/comments", "/threadedComment"]
                .iter()
                .any(|kind| rel.kind.ends_with(kind))
            {
                parts.push(rel.target);
            }
        }
        let mut headers = Vec::new();
        for table in &tables {
            headers.extend(self.move_table_columns(sheet, table, edit)?);
        }
        for target in &parts {
            self.move_coordinates(target, edit)?;
        }
        // An inserted table column's header cell holds its name.
        if !headers.is_empty() {
            let mut rows: BTreeMap<u32, BTreeMap<u32, &XlsxChange>> = BTreeMap::new();
            for header in &headers {
                if let XlsxChange::Cell { col, row, .. } = header {
                    rows.entry(*row).or_default().insert(*col, header);
                }
            }
            let bytes = rewrite_rows(&self.package, &part, &rows)?;
            self.package.replace_xml_part(&part, bytes)?;
        }
        // Each part with formulas, and the sheet its unprefixed references
        // are into: a worksheet's own, a table's worksheet, none for a chart
        // or the defined names.
        let mut homes: Vec<(String, Option<String>)> = Vec::new();
        for (name, part) in &self.worksheets {
            homes.push((part.clone(), Some(name.clone())));
            for rel in self.package.relationships(part)? {
                if !rel.external && rel.kind.ends_with("/table") {
                    homes.push((rel.target, Some(name.clone())));
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
                .map(|name| (name.to_owned(), None)),
        );
        homes.push((self.part.clone(), None));
        for (part, home) in homes {
            self.rewrite_formulas(&part, &|text: &str| {
                shift_axis(text, home.as_deref(), sheet, edit)
            })?;
        }
        Ok(())
    }

    /// Move one part's cell coordinates by a row or column edit: a
    /// worksheet's rows, cells and ranges, a table's range, a comment's cell.
    /// What the edit deletes goes, and a list it empties goes with it.
    fn move_coordinates(&mut self, part: &str, edit: &XlsxAxisEdit) -> Result<()> {
        /// Lists that go when the edit removes every entry.
        const LISTS: &[&str] = &[
            "mergeCells",
            "dataValidations",
            "hyperlinks",
            "cols",
            "conditionalFormattings",
            "protectedRanges",
            "ignoredErrors",
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
        if edits.is_empty() {
            return Ok(());
        }
        let value = splice(&bytes, edits).map_err(|_| refused("a part could not be rewritten"))?;
        self.package.replace_xml_part(part, value)?;
        Ok(())
    }

    /// Add or remove a table's columns for a column edit inside it, as Excel
    /// does, before its range moves: an inserted column takes a new id and
    /// the first free `ColumnN` name, and a deleted one goes with its
    /// calculated and totals formulas. An edit at or past either edge only
    /// moves the table, and one that deletes all of it refuses when the range
    /// moves. The header cells the inserted columns' names go in, as cell
    /// changes to sheet `sheet`.
    fn move_table_columns(
        &mut self,
        sheet: &str,
        part: &str,
        edit: &XlsxAxisEdit,
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
        let (left, right) = (range.first.0, range.last.0);
        let end = edit.at + edit.count - 1;
        // The place in the table the columns go in at or are deleted from.
        let at = if edit.delete {
            let (low, high) = (edit.at.max(left), end.min(right));
            if low > high || (low == left && high == right) {
                return Ok(Vec::new());
            }
            (low - left) as usize..(high - left + 1) as usize
        } else {
            if edit.at <= left || edit.at > right {
                return Ok(Vec::new());
            }
            let at = (edit.at - left) as usize;
            at..at
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
        if columns.len() != (right - left + 1) as usize {
            return Err(refused("a table's columns do not match its range"));
        }
        let mut edits = Vec::new();
        let mut headers = Vec::new();
        let count = if edit.delete {
            for column in &columns[at.clone()] {
                edits.push((column.span.clone(), Vec::new()));
            }
            columns.len() - at.len()
        } else {
            let mut names: HashSet<String> = columns
                .iter()
                .filter_map(|column| column.attr("name"))
                .map(str::to_lowercase)
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
            let mut n = 0;
            for col in edit.at..=end {
                let name = loop {
                    n += 1;
                    let name = format!("Column{n}");
                    if names.insert(name.to_lowercase()) {
                        break name;
                    }
                };
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
                XlsxChange::Cell { .. }
                | XlsxChange::Sheets { .. }
                | XlsxChange::Shift { .. }
                | XlsxChange::Formats { .. } => {
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

/// A range attribute (`B2:D9`, `B2`) after a row or column edit: `Some(None)`
/// when the edit deletes it, `None` when it does not read as a range.
fn moved_area(reference: &str, edit: &XlsxAxisEdit) -> Option<Option<String>> {
    let area = XlsxArea::parse(reference, XlsxLock::Unsupported)?;
    Some(edit.area(area.first, area.last).map(|(first, last)| {
        XlsxArea {
            first,
            last,
            ..area
        }
        .reference()
    }))
}

/// A space-separated range list after a row or column edit, without what it
/// deletes; a range that does not read as one stays.
fn moved_list(list: &str, edit: &XlsxAxisEdit) -> String {
    list.split_whitespace()
        .filter_map(|reference| {
            moved_area(reference, edit).unwrap_or_else(|| Some(reference.to_owned()))
        })
        .collect::<Vec<_>>()
        .join(" ")
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
