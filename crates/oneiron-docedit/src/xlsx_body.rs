//! SpreadsheetML workbook read and projection seam.
//! Entry: `project_xlsx`.
//! model, read and project own forwarded APIs; xlsx_error owns the error type.
//!
//! The XLSX face of a live office body (ARCH-0075: "XLSX is a map keyed by
//! sheet and address"). A read feeds the import: each worksheet's cells with
//! their values, formulas and formats and its tables, the defined names and
//! the workbook's cell formats. The projection writes a body's changes into the imported
//! package, rebuilding only the rows and names it touches, and writes every
//! formula without a cached value; the engine then recalculates the package,
//! or [`mark_full_calc`] has the opening application do it. A sheet layout
//! change renames, moves, adds and deletes worksheets first, retargeting
//! every formula that names a renamed or deleted sheet; row and column inserts
//! and deletes come next, moving cells, ranges and every reference into the
//! sheet, and a deleted reference reads `#REF!`. The cell formats a body
//! composed go into the stylesheet before any cell names them; a workbook
//! with none gets a minimal one. The body itself (its Loro document, actors
//! and forks) lives in the engine; this module knows only SpreadsheetML.

mod attachments;
mod axis;
mod coordinates;
mod header;
mod insert;
mod layout;
mod links;
mod model;
mod project;
mod read;
mod retain;
mod titles;

pub use header::header_rename;
pub use insert::calculated_fill;

use crate::edit::xml::{
    Splice, escape_attribute, insert_end, next_part, replace_text, set_attribute, splice,
};
use crate::ooxml::{
    DOCUMENT_RELATIONSHIPS as REL, Node, SPREADSHEET_MAIN as SML, XmlTree, escape_text,
};
use crate::retained_opc::{Limits, Package};
use crate::xlfn::{storage_form, ui_form};
pub use crate::xlsx_shift::{
    SheetFate, XlsxAxis, XlsxAxisEdit, drop_tables, retarget_sheets, shift_axis,
};
use crate::xlsx_shift::{drop_table_columns, shift_formula};
use crate::xlsx_styles::write_formats;
pub use crate::xlsx_styles::{
    XlsxBorder, XlsxColor, XlsxEdge, XlsxFill, XlsxFont, XlsxFormat, XlsxNumberFormat, check_format,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub use crate::xlsx_error::XlsxBodyError;
use model::{MAX_COLUMN, MAX_ROW, cell_ref, column_span, free_column_names};
pub use model::{
    MAX_FORMULA_CHARS, MAX_TEXT_CHARS, XlsxArea, XlsxBook, XlsxCell, XlsxChange, XlsxLock,
    XlsxName, XlsxProjection, XlsxSheet, XlsxSheetPlan, XlsxSheetVisibility, XlsxStyle, XlsxTable,
    XlsxTableShift, XlsxValue, a1, check_cell, check_name, check_sheet_name, parse_a1,
    shift_axis_formula,
};
pub use project::{mark_full_calc, project_xlsx};
pub use read::read_xlsx_cells;
use read::{names, string_item, styles};

const WORKSHEET_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml";
const WORKSHEET_KIND: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet";
const EXTENDED_PROPERTIES: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties";
/// A worksheet drawing's anchors.
const XDR: &str = "http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing";
/// The Excel elements of a legacy VML drawing (a note's cell and box).
const VML_EXCEL: &str = "urn:schemas-microsoft-com:office:excel";
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

type Result<T> = std::result::Result<T, XlsxBodyError>;

/// An opened workbook package.
struct Book {
    package: Package,
    /// The workbook part.
    part: String,
    /// Every sheet's name in workbook order, which `localSheetId` indexes.
    order: Vec<String>,
    /// Worksheet name → part.
    worksheets: BTreeMap<String, String>,
    /// Sheet name → whether its tab shows; a visible sheet may be absent.
    visibility: BTreeMap<String, XlsxSheetVisibility>,
    shared: Vec<String>,
    date1904: bool,
    names: Vec<XlsxName>,
    /// The stylesheet part, when the workbook has one.
    styles_part: Option<String>,
    styles: Vec<XlsxStyle>,
    /// What the projection adapted, for its receipt.
    effects: Vec<String>,
}

impl Book {
    fn open(bytes: &[u8], limits: Limits, resources: &crate::resource::Resources) -> Result<Self> {
        let package = Package::open(bytes, limits, resources)?;
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
        let mut visibility = BTreeMap::new();
        if let Some((list, _)) = tree.child(0, SML, "sheets")? {
            for (_, sheet) in tree
                .children(list)
                .filter(|(_, node)| node.is(SML, "sheet"))
            {
                let name = sheet.attr("name").ok_or(refused("a sheet has no name"))?;
                order.push(name.to_owned());
                visibility.insert(
                    name.to_owned(),
                    XlsxSheetVisibility::from_state(sheet.attr("state")),
                );
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
        // With no stylesheet every cell reads in the default format, so a
        // body may compose from it; the first composed format seeds one.
        let styles = match &styles_part {
            Some(part) => styles(&parse(&package, part)?)?,
            None => vec![XlsxStyle {
                num_fmt: 0,
                format: None,
            }],
        };
        let names = names(&tree, &order)?;
        Ok(Self {
            package,
            part,
            order,
            worksheets,
            visibility,
            shared,
            date1904,
            names,
            styles_part,
            styles,
            effects: Vec::new(),
        })
    }
}

/// Write `rows`' changes into a worksheet's `sheetData` (FIX 8571): a
/// stored cell is patched in place ([`retain::patch_cell`]), a new cell goes
/// in column order before the row's other content, and a new row in row
/// order. Every row's attributes and extensions, every untouched cell and
/// the markup between them keep their bytes. `restyled` (column, row) cells
/// are written as their format alone.
fn rewrite_rows(
    package: &Package,
    part: &str,
    rows: &BTreeMap<u32, BTreeMap<u32, &XlsxChange>>,
    restyled: &BTreeSet<(u32, u32)>,
) -> Result<Vec<u8>> {
    let bytes = package
        .part(part)?
        .ok_or(refused("a worksheet part is missing"))?;
    let tree = XmlTree::parse(&bytes, package.resources())?;
    let (data, data_node) = tree
        .child(0, SML, "sheetData")?
        .ok_or(refused("a worksheet has no sheetData"))?;
    let mut pending: BTreeMap<u32, &BTreeMap<u32, &XlsxChange>> =
        rows.iter().map(|(row, line)| (*row, line)).collect();
    // Each stored row's span by its number, and the end of the last one.
    let mut held_rows: BTreeMap<u32, std::ops::Range<usize>> = BTreeMap::new();
    let mut rows_end = None;
    let mut edits: Vec<Splice> = Vec::new();
    for (index, row) in tree.children(data).filter(|(_, node)| node.is(SML, "row")) {
        let number = row
            .attr("r")
            .and_then(|r| r.trim().parse::<u32>().ok())
            .ok_or(refused("a worksheet row has no number"))?;
        if held_rows.insert(number, row.span.clone()).is_some() {
            return Err(refused("a worksheet repeats a row"));
        }
        rows_end = Some(row.span.end);
        let Some(changes) = pending.remove(&number) else {
            continue;
        };
        // Each stored cell (its index and node) by its column, and the end
        // of the last one.
        let mut cells: BTreeMap<u32, (usize, &Node)> = BTreeMap::new();
        let mut cells_end = None;
        for (at, cell) in tree.children(index).filter(|(_, node)| node.is(SML, "c")) {
            let col = cell
                .attr("r")
                .and_then(cell_ref)
                .ok_or(refused("a worksheet cell has no reference"))?
                .0;
            cells.insert(col, (at, cell));
            cells_end = Some(cell.span.end);
        }
        // New cells by where they go: before a stored cell or the row's
        // first other child, else at its end (`None`).
        let mut added: BTreeMap<Option<usize>, Vec<u8>> = BTreeMap::new();
        let cell_name = row.child_name("c");
        for (col, change) in changes {
            match cells.get(col) {
                Some(&(_, cell)) if restyled.contains(&(*col, number)) => {
                    if let XlsxChange::Cell { style, .. } = change {
                        edits.push((cell.span.clone(), restyle(&bytes, cell, *style)));
                    }
                }
                Some(&(at, _)) => edits.extend(retain::patch_cell(&bytes, &tree, at, change)?),
                None => {
                    let Some(xml) = cell_xml(&cell_name, *col, number, change)? else {
                        continue;
                    };
                    let point = cells
                        .range(col + 1..)
                        .next()
                        .map(|(_, (_, cell))| cell.span.start)
                        .or(cells_end)
                        .or_else(|| tree.children(index).next().map(|(_, node)| node.span.start));
                    added.entry(point).or_default().extend(xml.into_bytes());
                }
            }
        }
        for (point, xml) in added {
            edits.push(match point {
                Some(at) => (at..at, xml),
                None => insert_end(&bytes, row, &xml),
            });
        }
    }
    let row_name = data_node.child_name("row");
    let cell_name = data_node.child_name("c");
    let mut added: BTreeMap<Option<usize>, Vec<u8>> = BTreeMap::new();
    for (number, changes) in pending {
        let mut cells = String::new();
        for (col, change) in changes {
            if let Some(cell) = cell_xml(&cell_name, *col, number, change)? {
                cells.push_str(&cell);
            }
        }
        if cells.is_empty() {
            continue;
        }
        let point = held_rows
            .range(number + 1..)
            .next()
            .map(|(_, span)| span.start)
            .or(rows_end);
        added
            .entry(point)
            .or_default()
            .extend(format!("<{row_name} r=\"{number}\">{cells}</{row_name}>").into_bytes());
    }
    for (point, xml) in added {
        edits.push(match point {
            Some(at) => (at..at, xml),
            None => insert_end(&bytes, data_node, &xml),
        });
    }
    splice(&bytes, edits).map_err(|_| refused("a worksheet could not be rewritten"))
}

/// A stored cell element with only its format changed: its `s` set, or
/// removed for none, and every other byte kept.
fn restyle(bytes: &[u8], cell: &crate::ooxml::Node, style: Option<u32>) -> Vec<u8> {
    let (range, value) = match (style, cell.attr_spans.get("s")) {
        (Some(style), _) => set_attribute(bytes, cell, "s", &style.to_string()),
        (None, Some(span)) => {
            let start = if span.start > 0 && bytes[span.start - 1].is_ascii_whitespace() {
                span.start - 1
            } else {
                span.start
            };
            (start..span.end, Vec::new())
        }
        (None, None) => return bytes[cell.span.clone()].to_vec(),
    };
    let mut out = bytes[cell.span.start..range.start].to_vec();
    out.extend(value);
    out.extend_from_slice(&bytes[range.end..cell.span.end]);
    out
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
    Ok(XmlTree::parse(&bytes, package.resources())?)
}

/// A range attribute (`B2:D9`, `B2`, the whole columns `A:C` or rows `2:5`)
/// after a row or column edit: `Some(None)` when the edit deletes it, `None`
/// when it does not read as a range.
fn moved_area(reference: &str, edit: &XlsxAxisEdit) -> Option<Option<String>> {
    let Some(area) = XlsxArea::parse(reference, XlsxLock::Unsupported) else {
        return moved_lines(reference, edit);
    };
    Some(edit.area(area.first, area.last).map(|(first, last)| {
        XlsxArea {
            first,
            last,
            ..area
        }
        .reference()
    }))
}

/// Whole columns (`A:C`, `$B:$B`) or whole rows (`2:5`) after a row or
/// column edit, written as they were: an edit along the other axis leaves
/// them, and one along theirs moves or shrinks them. `Some(None)` when the
/// edit deletes them all, `None` when the reference is neither.
fn moved_lines(reference: &str, edit: &XlsxAxisEdit) -> Option<Option<String>> {
    let side = |text: &str| -> Option<(bool, XlsxAxis, u32)> {
        let (fixed, rest) = match text.trim().strip_prefix('$') {
            Some(rest) => (true, rest),
            None => (false, text.trim()),
        };
        if !rest.is_empty() && rest.len() <= 3 && rest.bytes().all(|b| b.is_ascii_uppercase()) {
            let col = rest
                .bytes()
                .fold(0u32, |sum, byte| sum * 26 + u32::from(byte - b'A' + 1));
            return (col <= MAX_COLUMN).then_some((fixed, XlsxAxis::Column, col));
        }
        if rest.starts_with('0') || !rest.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let row = rest.parse::<u32>().ok()?;
        (1..=MAX_ROW)
            .contains(&row)
            .then_some((fixed, XlsxAxis::Row, row))
    };
    let (first, last) = reference.split_once(':')?;
    let ((first_fixed, axis, a), (last_fixed, other, b)) = (side(first)?, side(last)?);
    if axis != other {
        return None;
    }
    if axis != edit.axis {
        return Some(Some(reference.to_owned()));
    }
    let write = |fixed: bool, at: u32| {
        let dollar = if fixed { "$" } else { "" };
        match axis {
            // The column's letters: its row-1 cell without the `1`.
            XlsxAxis::Column => {
                let cell = a1(at, 1);
                format!("{dollar}{}", &cell[..cell.len() - 1])
            }
            XlsxAxis::Row => format!("{dollar}{at}"),
        }
    };
    Some(
        edit.range(a.min(b), a.max(b))
            .map(|(low, high)| format!("{}:{}", write(first_fixed, low), write(last_fixed, high))),
    )
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

/// A part whose formulas follow a sheet's edits: the sheet its unprefixed
/// references are into (a worksheet's own, a table's worksheet, none for a
/// chart or the defined names), and the table its unqualified structured
/// references (`[@Price]`) are to: a table part's own, or for a worksheet
/// cell the table whose range holds it.
struct FormulaHome {
    part: String,
    sheet: Option<String>,
    /// A worksheet's tables, as its part holds them now.
    tables: Vec<XlsxTable>,
    own: Option<String>,
}

impl FormulaHome {
    /// The table a formula at `at` (a worksheet cell) belongs to.
    fn owner(&self, at: Option<(u32, u32)>) -> Option<&str> {
        self.own.as_deref().or_else(|| {
            let (col, row) = at?;
            self.tables
                .iter()
                .find(|table| table.contains(col, row))
                .map(|table| table.name.as_str())
        })
    }
}

/// A table's columns a column edit deleted.
struct LostColumns {
    /// The table's id, and the name formulas call it by.
    id: u32,
    name: String,
    /// Each deleted column's id and name.
    columns: Vec<(u32, String)>,
}

/// What becomes of a pivot cache's worksheet source.
enum SourceFate {
    Keep,
    /// Its sheet, renamed.
    Sheet(String),
    /// Its range, moved.
    Range(String),
    /// Gone, as it was named (a sheet, a range or a table).
    Lost(String),
}

/// Remove attribute `name` and the space before it; `None` when it is
/// absent.
fn drop_attribute(bytes: &[u8], node: &Node, name: &str) -> Option<Splice> {
    let span = node.attr_spans.get(name)?;
    let start = if span.start > 0 && bytes[span.start - 1].is_ascii_whitespace() {
        span.start - 1
    } else {
        span.start
    };
    Some((start..span.end, Vec::new()))
}

/// Where a view's cell goes after a row or column edit: a deleted one's
/// place is the first line after the edit, and one an insert pushes off the
/// sheet stops at its edge.
fn kept_cell(at: (u32, u32), edit: &XlsxAxisEdit) -> (u32, u32) {
    edit.cell(at).unwrap_or_else(|| {
        let (line, last) = match edit.axis {
            XlsxAxis::Row => (at.1, MAX_ROW),
            XlsxAxis::Column => (at.0, MAX_COLUMN),
        };
        let to = if edit.delete { edit.at.min(line) } else { last };
        match edit.axis {
            XlsxAxis::Row => (at.0, to),
            XlsxAxis::Column => (to, at.1),
        }
    })
}

fn truthy(value: &str) -> bool {
    matches!(value.trim(), "1" | "true")
}

fn refused(reason: &'static str) -> XlsxBodyError {
    XlsxBodyError::Refused(reason)
}
