//! A rewritten chart's rebuilt workbook (OF-510, FIX 3493, FIX 6714): the
//! dataset its data sheet holds (each category set's levels, then each
//! series' x values and values, under a header row), the references each
//! series writes into it, and, when the chart's own workbook is rebuilt,
//! that sheet added beside the workbook's own sheets and shown first, so
//! nothing the workbook held is lost (ARCH-0077: "Keep every zip entry with
//! its original bytes").

use super::layout::{CategorySet, Data, Wanted};
use crate::design_plan::{Cell, Column, ColumnKind, Dataset};
use crate::edit::xml::{self, R};
use crate::ooxml::SPREADSHEET_MAIN as SML;
use crate::retained_opc::{Limits, Package};
use crate::xlsx_body::{
    XlsxChange, XlsxSheetPlan, XlsxSheetVisibility, XlsxValue, project_xlsx, read_xlsx_cells,
};
use std::collections::BTreeSet;

fn letters(mut col: u32) -> String {
    let mut out = Vec::new();
    while col > 0 {
        out.push(b'A' + ((col - 1) % 26) as u8);
        col = (col - 1) / 26;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

/// A reference to the rectangle from `(col, first)` to `(last_col, last)`
/// on `sheet`; one cell when both corners are one.
fn area(sheet: &str, (col, first): (u32, usize), (last_col, last): (u32, usize)) -> String {
    let sheet = format!("'{}'", sheet.replace('\'', "''"));
    let from = format!("${}${first}", letters(col));
    if (col, first) == (last_col, last) {
        format!("{sheet}!{from}")
    } else {
        format!("{sheet}!{from}:${}${last}", letters(last_col))
    }
}

fn formula(sheet: &str, col: u32, first: usize, last: usize) -> String {
    area(sheet, (col, first), (col, last))
}

/// The references one rewritten series writes: its name, its categories
/// or x values, its values, a bubble series' sizes. `None` writes a
/// literal.
#[derive(Debug, Clone, Default)]
pub(super) struct Refs {
    pub(super) name: Option<String>,
    pub(super) first: Option<String>,
    pub(super) values: Option<String>,
    pub(super) size: Option<String>,
}

impl Refs {
    /// A series' references into a rebuilt workbook's data sheet `sheet`:
    /// its name in row 1 over its values column, and its x values column (a
    /// scatter series') or the block of the category set it draws, one
    /// column per level.
    pub(super) fn rebuilt(line: &Data, sets: &[CategorySet], sheet: &str) -> Self {
        let first = match (&line.x, line.x_col) {
            (Some(x), Some(col)) => Some(formula(sheet, col, 2, x.len() + 1)),
            _ => line
                .set
                .and_then(|set| sets.get(set))
                .filter(|set| set.count() > 0)
                .map(|set| {
                    area(
                        sheet,
                        (set.col, 2),
                        (
                            set.col.saturating_add(set.width().saturating_sub(1)),
                            set.count() + 1,
                        ),
                    )
                }),
        };
        Self {
            name: Some(formula(sheet, line.y_col, 1, 1)),
            first,
            values: Some(formula(sheet, line.y_col, 2, line.values.len() + 1)),
            size: line
                .size
                .as_ref()
                .zip(line.size_col)
                .map(|(size, col)| formula(sheet, col, 2, size.len() + 1)),
        }
    }
}

/// The rebuilt workbook's data sheet: each category set's levels (the
/// outermost first), then each series' x column (a scatter or bubble
/// series'), values column and size column (a bubble series'), under a
/// header row.
pub(super) fn workbook_dataset(wanted: &Wanted) -> Dataset {
    let Wanted { sets, data, .. } = wanted;
    let mut columns = Vec::new();
    let mut cells: Vec<Vec<Cell>> = Vec::new();
    let column = |name: String, kind| Column {
        name,
        kind,
        unit: None,
        format: None,
    };
    for set in sets {
        let kind = if set.numeric {
            ColumnKind::Number
        } else {
            ColumnKind::Text
        };
        for level in set.levels.iter().rev() {
            columns.push(column(String::new(), kind));
            cells.push(level.clone());
        }
    }
    for line in data {
        if let Some(x) = &line.x {
            // Text x values stay text cells (FIX 9277).
            let kind = if line.x_text {
                ColumnKind::Text
            } else {
                ColumnKind::Number
            };
            columns.push(column(format!("{} (x)", line.name), kind));
            cells.push(x.clone());
        }
        columns.push(column(line.name.clone(), ColumnKind::Number));
        cells.push(line.values.clone());
        if let Some(size) = &line.size {
            columns.push(column(format!("{} (size)", line.name), ColumnKind::Number));
            cells.push(size.clone());
        }
    }
    let height = cells.iter().map(Vec::len).max().unwrap_or(0);
    let rows: Vec<Vec<Cell>> = (0..height)
        .map(|row| {
            cells
                .iter()
                .map(|col| col.get(row).cloned().unwrap_or(Cell::Missing))
                .collect()
        })
        .collect();
    Dataset {
        id: String::new(),
        columns,
        rows,
        missing: None,
        sources: Vec::new(),
        merges: Vec::new(),
    }
}

/// An embedded workbook's main part and its sheets, in workbook order:
/// each one's name and part (`None` for one its relationships do not
/// reach).
fn sheets(package: &Package) -> Option<(String, Vec<(String, Option<String>)>)> {
    let book = package
        .relationships("")
        .ok()?
        .into_iter()
        .find(|rel| !rel.external && rel.kind.ends_with("/officeDocument"))?
        .target;
    let links = package.relationships(&book).ok()?;
    let (_, tree) = xml::read(package, &book).ok()?;
    let list = xml::child(&tree, 0, SML, "sheets")?;
    let sheets = tree.nodes[list]
        .children
        .iter()
        .filter(|&&at| tree.nodes[at].is(SML, "sheet"))
        .filter_map(|&at| {
            let name = tree.nodes[at].attr("name")?.to_owned();
            let part = tree.nodes[at].attr_ns(R, "id").and_then(|id| {
                links
                    .iter()
                    .find(|rel| rel.id == id && !rel.external)
                    .map(|rel| rel.target.clone())
            });
            Some((name, part))
        })
        .collect();
    Some((book, sheets))
}

/// The name the rebuilt data takes in the chart's own workbook `bytes`:
/// the first of `Sheet1`, `Sheet2`, … no sheet of it holds, in any case.
/// `None` when the workbook does not read: the rebuild starts afresh.
pub(super) fn free_sheet(bytes: &[u8], limits: Limits) -> Option<String> {
    let package = Package::open(bytes, limits).ok()?;
    let (_, sheets) = sheets(&package)?;
    let taken: BTreeSet<String> = sheets.iter().map(|(name, _)| name.to_lowercase()).collect();
    (1_u64..)
        .map(|n| format!("Sheet{n}"))
        .find(|name| !taken.contains(&name.to_lowercase()))
}

/// The chart's own workbook `source` with the rebuilt `dataset` on a new
/// sheet `sheet` after its own, which it shows first (the workbook's active
/// tab, the one selected tab): every other sheet, name, table, style and
/// formula keeps its bytes, but for the selection moved off the sheets
/// that held it. `None` when the workbook editor refuses it.
pub(super) fn beside(
    source: &[u8],
    dataset: &Dataset,
    sheet: &str,
    limits: Limits,
) -> Option<Vec<u8>> {
    let book = read_xlsx_cells(source, limits).ok()?;
    let mut layout: Vec<XlsxSheetPlan> = book
        .sheets
        .iter()
        .map(|held| XlsxSheetPlan {
            name: held.name.clone(),
            source: Some(held.name.clone()),
            visibility: held.visibility,
        })
        .collect();
    layout.push(XlsxSheetPlan {
        name: sheet.to_owned(),
        source: None,
        visibility: XlsxSheetVisibility::Visible,
    });
    let mut changes = vec![XlsxChange::Sheets { sheets: layout }];
    let header = dataset
        .columns
        .iter()
        .map(|column| Cell::Text(crate::native_patch::header(column)));
    let rows = std::iter::once(header.collect::<Vec<_>>()).chain(dataset.rows.iter().cloned());
    for (row, cells) in rows.enumerate() {
        for (col, cell) in cells.into_iter().enumerate() {
            let value = match cell {
                Cell::Missing => continue,
                Cell::Number(value) => XlsxValue::Number(value),
                Cell::Text(text) | Cell::Date(text) => XlsxValue::Text(text),
            };
            changes.push(XlsxChange::Cell {
                sheet: sheet.to_owned(),
                col: u32::try_from(col + 1).ok()?,
                row: u32::try_from(row + 1).ok()?,
                value,
                formula: None,
                style: None,
            });
        }
    }
    let projected = project_xlsx(source, &changes, limits).ok()?.bytes;
    shown_first(&projected, sheet, limits)
}

/// `bytes` with `sheet` the workbook's active tab and its only selected
/// one, as Edit Data then opens it.
fn shown_first(bytes: &[u8], sheet: &str, limits: Limits) -> Option<Vec<u8>> {
    let mut package = Package::open(bytes, limits).ok()?;
    let (book, sheets) = sheets(&package)?;
    let tab = sheets.iter().position(|(name, _)| name == sheet)?;
    let (book_bytes, tree) = xml::read(&package, &book).ok()?;
    let edit = match xml::child(&tree, 0, SML, "bookViews")
        .and_then(|views| xml::child(&tree, views, SML, "workbookView"))
    {
        Some(view) => xml::set_attribute(
            &book_bytes,
            &tree.nodes[view],
            "activeTab",
            &tab.to_string(),
        ),
        None => {
            // CT_Workbook: fileVersion?, fileSharing?, workbookPr?,
            // workbookProtection?, bookViews?, sheets.
            let list = xml::child(&tree, 0, SML, "sheets")?;
            let at = tree.nodes[list].span.start;
            let p = match xml::prefix(&tree.nodes[list]) {
                "" => String::new(),
                prefix => format!("{prefix}:"),
            };
            (
                at..at,
                format!(r#"<{p}bookViews><{p}workbookView activeTab="{tab}"/></{p}bookViews>"#)
                    .into_bytes(),
            )
        }
    };
    package
        .replace_xml_part(&book, xml::splice(&book_bytes, vec![edit]).ok()?)
        .ok()?;
    for (name, part) in &sheets {
        let Some(part) = part else {
            continue;
        };
        let Ok((sheet_bytes, tree)) = xml::read(&package, part) else {
            continue;
        };
        let selected = name == sheet;
        let views: Vec<usize> = xml::child(&tree, 0, SML, "sheetViews")
            .map(|list| {
                tree.nodes[list]
                    .children
                    .iter()
                    .copied()
                    .filter(|&at| tree.nodes[at].is(SML, "sheetView"))
                    .collect()
            })
            .unwrap_or_default();
        let mut edits = Vec::new();
        if selected && views.is_empty() {
            // CT_Worksheet: sheetPr?, dimension?, sheetViews?, ...,
            // sheetData.
            let data = xml::child(&tree, 0, SML, "sheetData")?;
            let at = tree.nodes[data].span.start;
            let p = match xml::prefix(&tree.nodes[data]) {
                "" => String::new(),
                prefix => format!("{prefix}:"),
            };
            edits.push((
                at..at,
                format!(
                    r#"<{p}sheetViews><{p}sheetView tabSelected="1" workbookViewId="0"/></{p}sheetViews>"#
                )
                .into_bytes(),
            ));
        }
        for &view in &views {
            let held = matches!(
                tree.nodes[view].attr("tabSelected").map(str::trim),
                Some("1" | "true")
            );
            if held != selected {
                edits.push(xml::set_attribute(
                    &sheet_bytes,
                    &tree.nodes[view],
                    "tabSelected",
                    if selected { "1" } else { "0" },
                ));
            }
        }
        if !edits.is_empty() {
            package
                .replace_xml_part(part, xml::splice(&sheet_bytes, edits).ok()?)
                .ok()?;
        }
    }
    package.export().ok()
}
