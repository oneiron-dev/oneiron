//! What inserted rows and columns take from their neighbours, as Excel's
//! insert gives it by default (FIX 3695): a row's format and height, a
//! column's width and format, and inside a table's data area each
//! calculated column's formula. The neighbour is the row above or the
//! column to the left; at the sheet's first row or column, the one after
//! the inserted ones, as the body's cell formats have it.
use super::{
    Book, MAX_COLUMN, MAX_ROW, Result, SML, XlsxAxis, XlsxAxisEdit, XlsxChange, XlsxTable,
    XlsxValue, refused, rewrite_rows, truthy,
};
use crate::edit::xml::{Splice, splice};
use crate::ooxml::{Node, XmlTree};
use crate::xlsx_shift::shift_formula;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// A row's attributes an inserted row takes from its neighbour.
const ROW_FORMAT: &[&str] = &["s", "customFormat", "ht", "customHeight"];
/// A column range's attributes an inserted column takes from its
/// neighbour's.
const COLUMN_FORMAT: &[&str] = &["width", "customWidth", "style"];

/// Rows or columns `first..=last` with their own size or format (FIX 9081):
/// one row each as a worksheet stores them, or one column range.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct XlsxLines {
    pub first: u32,
    pub last: u32,
    /// A row's height in points, or a column's width in characters.
    pub size: Option<f64>,
    /// The cell format their empty cells show, an index into the workbook's.
    pub style: Option<u32>,
}

/// `lines`, the rows or the columns along `edit`'s axis, after the edit as
/// the export leaves the worksheet's rows and column ranges: each moves, a
/// range an insert lands inside widens, and a delete shrinks or removes what
/// it covers; an insert's new lines take the size and format of the lines
/// holding their neighbour, unless those already span them.
#[must_use]
pub fn shift_lines(lines: &[XlsxLines], edit: &XlsxAxisEdit) -> Vec<XlsxLines> {
    let mut out: Vec<XlsxLines> = lines
        .iter()
        .filter_map(|line| {
            let (first, last) = edit.range(line.first, line.last)?;
            Some(XlsxLines {
                first,
                last,
                ..*line
            })
        })
        .collect();
    if edit.delete {
        return out;
    }
    let (source, last) = (neighbour(edit), last_inserted(edit));
    if let Some(like) = out
        .iter()
        .find(|line| (line.first..=line.last).contains(&source))
        .copied()
        && !(like.first..=like.last).contains(&edit.at)
    {
        out.push(XlsxLines {
            first: edit.at,
            last,
            ..like
        });
        out.sort_by_key(|line| line.first);
    }
    out
}

/// A worksheet's rows with their own height or format, one each, and its
/// column ranges with their own width or format. A row's format holds only
/// where it says so (`customFormat`).
pub(super) fn sheet_lines(tree: &XmlTree) -> Result<(Vec<XlsxLines>, Vec<XlsxLines>)> {
    let number = |node: &Node, name: &str| node.attr(name)?.trim().parse::<u32>().ok();
    let size = |node: &Node, name: &str| {
        node.attr(name)?
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|size| size.is_finite())
    };
    let mut rows = Vec::new();
    if let Some((data, _)) = tree.child(0, SML, "sheetData")? {
        for (_, row) in tree.children(data).filter(|(_, node)| node.is(SML, "row")) {
            let Some(at) = number(row, "r") else {
                continue;
            };
            let style = number(row, "s").filter(|_| row.attr("customFormat").is_some_and(truthy));
            let height = size(row, "ht");
            if height.is_some() || style.is_some() {
                rows.push(XlsxLines {
                    first: at,
                    last: at,
                    size: height,
                    style,
                });
            }
        }
    }
    let mut columns = Vec::new();
    for range in tree
        .children(0)
        .filter(|(_, node)| node.is(SML, "cols"))
        .flat_map(|(at, _)| tree.children(at))
        .map(|(_, node)| node)
        .filter(|node| node.is(SML, "col"))
    {
        let (Some(min), Some(max)) = (number(range, "min"), number(range, "max")) else {
            continue;
        };
        let (width, style) = (size(range, "width"), number(range, "style"));
        if width.is_some() || style.is_some() {
            columns.push(XlsxLines {
                first: min.min(max),
                last: min.max(max),
                size: width,
                style,
            });
        }
    }
    Ok((rows, columns))
}

/// The row or column an insert's new lines take after, as the edit leaves
/// the sheet.
fn neighbour(edit: &XlsxAxisEdit) -> u32 {
    if edit.at > 1 {
        edit.at - 1
    } else {
        edit.at.saturating_add(edit.count)
    }
}

/// The last row or column an insert adds.
fn last_inserted(edit: &XlsxAxisEdit) -> u32 {
    let max = match edit.axis {
        XlsxAxis::Row => MAX_ROW,
        XlsxAxis::Column => MAX_COLUMN,
    };
    edit.at.saturating_add(edit.count - 1).min(max)
}

/// The formulas Excel writes into the rows `edit` inserted inside
/// `table`'s data area: each calculated column's formula, read at the
/// table's first data row as the edit moved it (`anchor`) and moved to each
/// inserted row. `table` is as the edit leaves it, its calculated formulas
/// moved by the edit too. Each is `(column, row, formula)`.
#[must_use]
pub fn calculated_fill(
    table: &XlsxTable,
    anchor: u32,
    edit: &XlsxAxisEdit,
) -> Vec<(u32, u32, String)> {
    if edit.axis != XlsxAxis::Row || edit.delete || table.calculated.is_empty() {
        return Vec::new();
    }
    let top = edit.at.max(table.first.1.saturating_add(table.header_rows));
    let bottom = last_inserted(edit).min(table.last.1.saturating_sub(table.totals_rows));
    let mut out = Vec::new();
    for row in top..=bottom {
        for (col, formula) in (table.first.0..=table.last.0).zip(&table.calculated) {
            let Some(formula) = formula else {
                continue;
            };
            if let Some(moved) = shift_formula(formula, i64::from(row) - i64::from(anchor), 0) {
                out.push((col, row, moved));
            }
        }
    }
    out
}

impl Book {
    /// Give the rows or columns `edit` inserted into worksheet `part` their
    /// neighbour's format: a row its row format and height, a column its
    /// range's width and format, in a range of its own. Nothing else of the
    /// neighbour (cells, hidden state, outline level) is copied. Run after
    /// the part's coordinates moved.
    pub(super) fn inherit_lines(&mut self, part: &str, edit: &XlsxAxisEdit) -> Result<()> {
        if edit.delete {
            return Ok(());
        }
        let bytes = self
            .package
            .part(part)?
            .ok_or(refused("a worksheet part is missing"))?;
        let tree = XmlTree::parse(&bytes, self.package.resources())?;
        let edits = match edit.axis {
            XlsxAxis::Row => row_shells(&bytes, &tree, edit)?,
            XlsxAxis::Column => column_range(&bytes, &tree, edit),
        };
        if edits.is_empty() {
            return Ok(());
        }
        let value =
            splice(&bytes, edits).map_err(|_| refused("a worksheet could not be rewritten"))?;
        self.package.replace_xml_part(part, value)?;
        Ok(())
    }

    /// Write each calculated column's formula into the rows `edit`
    /// inserted inside a table's data area on worksheet `sheet`
    /// ([`calculated_fill`]), each in the format of the neighbour row's
    /// writable cell in its column. `anchors` holds each table's first data
    /// row as the edit moved it, by its name in lower case. Run after every
    /// formula followed the edit.
    pub(super) fn fill_calculated(
        &mut self,
        sheet: &str,
        part: &str,
        edit: &XlsxAxisEdit,
        anchors: &[(String, u32)],
    ) -> Result<()> {
        let tables = self.tables(part)?;
        let mut fills = Vec::new();
        for table in &tables {
            let name = table.name.to_lowercase();
            if let Some((_, anchor)) = anchors.iter().find(|(held, _)| *held == name) {
                fills.extend(calculated_fill(table, *anchor, edit));
            }
        }
        if fills.is_empty() {
            return Ok(());
        }
        let source = neighbour(edit);
        let (cells, _, _) = self.sheet(part)?;
        let like: HashMap<u32, Option<u32>> = cells
            .iter()
            .filter(|cell| cell.row == source && cell.locked.is_none())
            .map(|cell| (cell.col, cell.style))
            .collect();
        let changes: Vec<XlsxChange> = fills
            .into_iter()
            .map(|(col, row, formula)| XlsxChange::Cell {
                sheet: sheet.to_owned(),
                col,
                row,
                value: XlsxValue::Blank,
                formula: Some(formula),
                style: like.get(&col).copied().flatten(),
            })
            .collect();
        let mut rows: BTreeMap<u32, BTreeMap<u32, &XlsxChange>> = BTreeMap::new();
        for change in &changes {
            if let XlsxChange::Cell { col, row, .. } = change {
                rows.entry(*row).or_default().insert(*col, change);
            }
        }
        let bytes = rewrite_rows(&self.package, part, &rows, &BTreeSet::new())?;
        self.package.replace_xml_part(part, bytes)?;
        Ok(())
    }
}

/// The inserted rows, each an empty `row` with the neighbour row's format
/// and height attributes as written, before the first row past them.
fn row_shells(bytes: &[u8], tree: &XmlTree, edit: &XlsxAxisEdit) -> Result<Vec<Splice>> {
    let Some((data, _)) = tree.child(0, SML, "sheetData")? else {
        return Ok(Vec::new());
    };
    let (source, last) = (neighbour(edit), last_inserted(edit));
    let rows: Vec<(u32, &Node)> = tree
        .children(data)
        .filter(|(_, node)| node.is(SML, "row"))
        .filter_map(|(_, node)| Some((node.attr("r")?.trim().parse::<u32>().ok()?, node)))
        .collect();
    let Some(&(_, like)) = rows.iter().find(|(number, _)| *number == source) else {
        return Ok(Vec::new());
    };
    let format: Vec<u8> = ROW_FORMAT
        .iter()
        .filter_map(|name| like.attr_spans.get(*name))
        .flat_map(|span| [&b" "[..], &bytes[span.clone()]].concat())
        .collect();
    if format.is_empty()
        || rows
            .iter()
            .any(|(number, _)| (edit.at..=last).contains(number))
    {
        return Ok(Vec::new());
    }
    let mut shells = Vec::new();
    for number in edit.at..=last {
        shells.extend(format!("<{} r=\"{number}\"", like.qualified).into_bytes());
        shells.extend_from_slice(&format);
        shells.extend_from_slice(b"/>");
    }
    let Some(point) = rows
        .iter()
        .find(|(number, _)| *number > last)
        .map(|(_, node)| node.span.start)
        .or_else(|| rows.last().map(|(_, node)| node.span.end))
    else {
        return Ok(Vec::new());
    };
    Ok(vec![(point..point, shells)])
}

/// The inserted columns as a `col` range of their own with the width and
/// format attributes, as written, of the range holding the neighbour
/// column, beside it; none when that range already spans them.
fn column_range(bytes: &[u8], tree: &XmlTree, edit: &XlsxAxisEdit) -> Vec<Splice> {
    let (source, last) = (neighbour(edit), last_inserted(edit));
    let ranges = tree
        .children(0)
        .filter(|(_, node)| node.is(SML, "cols"))
        .flat_map(|(at, _)| tree.children(at))
        .map(|(_, node)| node)
        .filter(|node| node.is(SML, "col"));
    for range in ranges {
        let bound = |name: &str| range.attr(name)?.trim().parse::<u32>().ok();
        let (Some(min), Some(max)) = (bound("min"), bound("max")) else {
            continue;
        };
        if !(min..=max).contains(&source) {
            continue;
        }
        if (min..=max).contains(&edit.at) {
            return Vec::new();
        }
        let format: Vec<u8> = COLUMN_FORMAT
            .iter()
            .filter_map(|name| range.attr_spans.get(*name))
            .flat_map(|span| [&b" "[..], &bytes[span.clone()]].concat())
            .collect();
        if format.is_empty() {
            return Vec::new();
        }
        let mut element =
            format!("<{} min=\"{}\" max=\"{last}\"", range.qualified, edit.at).into_bytes();
        element.extend(format);
        element.extend_from_slice(b"/>");
        // After a range to the left, before one to the right.
        let point = if source < edit.at {
            range.span.end
        } else {
            range.span.start
        };
        return vec![(point..point, element)];
    }
    Vec::new()
}
