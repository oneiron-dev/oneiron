//! Shape changes to a written table or chart at export (OF-510). A table's
//! rows and columns are rewritten over its grid; a chart's plots, series and
//! categories are rewritten over its part, its caches and its embedded
//! workbook rebuilt from the live data (ARCH-0077: caches and workbooks are
//! projections of one dataset). What the live model does not name keeps its
//! bytes: a kept row's, column's or cell's properties, a kept series'
//! formatting, and the chart's titles, axes and legend.

use super::LiveError;
use super::held::{self, C, children};
use super::pptx::{
    ChartKind, ChartSeries, NodePayload, WRITTEN_COMBO, WRITTEN_FRAME, WRITTEN_TABLE,
};
use crate::design_plan::{Cell, Column, ColumnKind, Dataset};
use crate::edit::xml::{self, A, P, R};
use crate::native_patch::{Target, chart_data, chart_workbook, number};
use crate::ooxml::{Node, XmlTree, escape_text};
use crate::retained_opc::Package;
use std::ops::Range;

/// The one sheet of a rewritten chart's embedded workbook.
const SHEET: &str = "Sheet1";
/// A rewrite that does not read back as the live data refuses.
const READ_BACK: &str = "a rewritten chart does not read back as the live data";
/// The merge attributes a new cell never carries.
const MERGE: &[&str] = &["gridSpan", "rowSpan", "hMerge", "vMerge"];

fn piece<'b>(bytes: &'b [u8], tree: &XmlTree, at: usize) -> &'b [u8] {
    &bytes[tree.nodes[at].span.clone()]
}

fn close(node: &Node) -> Vec<u8> {
    format!("</{}>", node.qualified).into_bytes()
}

/// `node`'s open tag without the named attributes.
fn open_without(bytes: &[u8], node: &Node, names: &[&str]) -> Vec<u8> {
    let open = xml::open_tag(bytes, node);
    let base = node.span.start;
    let mut cuts: Vec<Range<usize>> = names
        .iter()
        .filter_map(|name| node.attr_spans.get(*name))
        .map(|span| {
            let mut start = span.start - base;
            while start > 0 && open[start - 1].is_ascii_whitespace() {
                start -= 1;
            }
            start..span.end - base
        })
        .collect();
    cuts.sort_by_key(|cut| cut.start);
    let mut out = Vec::with_capacity(open.len());
    let mut at = 0;
    for cut in cuts {
        if cut.start >= at && cut.end <= open.len() {
            out.extend_from_slice(&open[at..cut.start]);
            at = cut.end;
        }
    }
    out.extend_from_slice(&open[at..]);
    out
}

/// The graphic frame with this native id in a slide part.
fn frame_of(tree: &XmlTree, native: u32) -> Option<usize> {
    let id = native.to_string();
    (0..tree.nodes.len()).find(|&at| {
        tree.nodes[at].is(P, "graphicFrame")
            && xml::path(tree, at, &[(P, "nvGraphicFramePr"), (P, "cNvPr")])
                .is_some_and(|c_nv_pr| tree.nodes[c_nv_pr].attr("id") == Some(id.as_str()))
    })
}

/// Rewrite the table in `slide`'s frame `native` to the grid of `wanted`
/// (header row first, one cell per column). Kept rows and cells keep their
/// bytes, with merge spans clamped to the new grid; a new column takes the
/// last column's width, a new row the last row's height, and a new cell its
/// template cell's properties, no merge, and its text. The caller writes
/// the kept cells' text after.
pub(super) fn table(
    package: &mut Package,
    slide: &str,
    native: u32,
    wanted: &[Vec<String>],
) -> Result<(), LiveError> {
    let refuse = LiveError::Invalid(WRITTEN_TABLE);
    let (bytes, tree) = xml::read(package, slide)?;
    let frame = frame_of(&tree, native).ok_or(LiveError::Invalid(WRITTEN_FRAME))?;
    let tbl = held::table_of(&tree, frame).ok_or(LiveError::Invalid(WRITTEN_FRAME))?;
    let cols = wanted.first().map_or(0, Vec::len);
    if cols == 0 || wanted.iter().any(|row| row.len() != cols) {
        return Err(refuse);
    }
    let grid = xml::child(&tree, tbl, A, "tblGrid").ok_or(refuse.clone())?;
    let widths: Vec<usize> = children(&tree, grid, A, "gridCol").collect();
    let rows: Vec<usize> = children(&tree, tbl, A, "tr").collect();
    let (Some(&last_col), Some(&last_row)) = (widths.last(), rows.last()) else {
        return Err(refuse);
    };
    let col_name = tree.nodes[last_col].qualified.clone();
    let mut grid_xml = xml::open_tag(&bytes, &tree.nodes[grid]);
    for col in 0..cols {
        match widths.get(col) {
            Some(&kept) => grid_xml.extend_from_slice(piece(&bytes, &tree, kept)),
            None => grid_xml.extend(
                format!(
                    r#"<{col_name} w="{}"/>"#,
                    xml::escape_attribute(tree.nodes[last_col].attr("w").unwrap_or("0"))
                )
                .into_bytes(),
            ),
        }
    }
    grid_xml.extend(close(&tree.nodes[grid]));
    let mut rows_xml = Vec::new();
    for (row, line) in wanted.iter().enumerate() {
        let Some(&tr) = rows.get(row) else {
            let template: Vec<usize> = children(&tree, last_row, A, "tc").collect();
            rows_xml.extend(open_without(&bytes, &tree.nodes[last_row], &[]));
            for (col, text) in line.iter().enumerate() {
                let tc = *template
                    .get(col)
                    .or(template.last())
                    .ok_or(refuse.clone())?;
                rows_xml.extend(new_cell(&bytes, &tree, tc, text));
            }
            rows_xml.extend(close(&tree.nodes[last_row]));
            continue;
        };
        let cells: Vec<usize> = children(&tree, tr, A, "tc").collect();
        rows_xml.extend(xml::open_tag(&bytes, &tree.nodes[tr]));
        for (col, text) in line.iter().enumerate() {
            match cells.get(col) {
                Some(&tc) => rows_xml.extend(kept_cell(
                    &bytes,
                    &tree,
                    tc,
                    wanted.len() - row,
                    cols - col,
                )?),
                None => {
                    let tc = *cells.last().ok_or(refuse.clone())?;
                    rows_xml.extend(new_cell(&bytes, &tree, tc, text));
                }
            }
        }
        for &child in &tree.nodes[tr].children {
            if !tree.nodes[child].is(A, "tc") {
                rows_xml.extend_from_slice(piece(&bytes, &tree, child));
            }
        }
        rows_xml.extend(close(&tree.nodes[tr]));
    }
    let mut out = xml::open_tag(&bytes, &tree.nodes[tbl]);
    let mut placed = false;
    for &child in &tree.nodes[tbl].children {
        let node = &tree.nodes[child];
        if node.is(A, "tblGrid") {
            out.extend_from_slice(&grid_xml);
        } else if node.is(A, "tr") {
            if !placed {
                out.extend_from_slice(&rows_xml);
                placed = true;
            }
        } else {
            out.extend_from_slice(piece(&bytes, &tree, child));
        }
    }
    out.extend(close(&tree.nodes[tbl]));
    let next = xml::splice(&bytes, vec![(tree.nodes[tbl].span.clone(), out)])?;
    package.replace_xml_part(slide, next)?;
    let read = xml::read(package, slide)?.1;
    let shape = frame_of(&read, native)
        .and_then(|frame| held::table_cells(&read, frame))
        .map(|grid| (grid.len(), grid.iter().all(|row| row.len() == cols)));
    if shape != Some((wanted.len(), true)) {
        return Err(refuse);
    }
    Ok(())
}

/// A kept cell, its merge spans clamped to the rows and columns left.
fn kept_cell(
    bytes: &[u8],
    tree: &XmlTree,
    tc: usize,
    rows_left: usize,
    cols_left: usize,
) -> Result<Vec<u8>, LiveError> {
    let node = &tree.nodes[tc];
    let base = node.span.start;
    let mut edits = Vec::new();
    for (name, left) in [("gridSpan", cols_left), ("rowSpan", rows_left)] {
        if node
            .attr(name)
            .and_then(|span| span.trim().parse::<usize>().ok())
            .is_some_and(|span| span > left)
        {
            let (range, value) = xml::set_attribute(bytes, node, name, &left.max(1).to_string());
            edits.push((range.start - base..range.end - base, value));
        }
    }
    Ok(xml::splice(&bytes[node.span.clone()], edits)?)
}

/// A new cell from a template cell: its open tag without merge attributes,
/// its body and first paragraph's properties, its first run's properties
/// on each line of `text`, and its cell properties.
fn new_cell(bytes: &[u8], tree: &XmlTree, tc: usize, text: &str) -> Vec<u8> {
    let node = &tree.nodes[tc];
    let a = xml::prefix(node);
    let q = |name: &str| xml::qualify(a, name);
    let part = |at: Option<usize>| at.map_or(&[][..], |at| piece(bytes, tree, at));
    let body = xml::child(tree, tc, A, "txBody");
    let first = body.and_then(|body| xml::child(tree, body, A, "p"));
    let body_pr = body.and_then(|body| xml::child(tree, body, A, "bodyPr"));
    let list = body.and_then(|body| xml::child(tree, body, A, "lstStyle"));
    let p_pr = first.and_then(|p| xml::child(tree, p, A, "pPr"));
    let end = first.and_then(|p| xml::child(tree, p, A, "endParaRPr"));
    let r_pr = body
        .and_then(|body| held::within(tree, body).find(|&at| tree.nodes[at].is(A, "r")))
        .and_then(|run| xml::child(tree, run, A, "rPr"));
    let mut out = open_without(bytes, node, MERGE);
    out.extend(format!("<{}>", q("txBody")).into_bytes());
    match body_pr {
        Some(at) => out.extend_from_slice(piece(bytes, tree, at)),
        None => out.extend(format!("<{}/>", q("bodyPr")).into_bytes()),
    }
    out.extend_from_slice(part(list));
    for line in text.split('\n') {
        out.extend(format!("<{}>", q("p")).into_bytes());
        out.extend_from_slice(part(p_pr));
        if !line.is_empty() {
            out.extend(format!("<{}>", q("r")).into_bytes());
            out.extend_from_slice(part(r_pr));
            out.extend(
                format!(
                    "<{t}>{}</{t}></{r}>",
                    escape_text(line),
                    t = q("t"),
                    r = q("r")
                )
                .into_bytes(),
            );
        }
        out.extend_from_slice(part(end));
        out.extend(format!("</{}>", q("p")).into_bytes());
    }
    out.extend(format!("</{}>", q("txBody")).into_bytes());
    out.extend_from_slice(part(xml::child(tree, tc, A, "tcPr")));
    out.extend(close(node));
    out
}

/// One live series' data as the rewrite writes it.
struct Data {
    name: String,
    /// Workbook columns (1-based) of its x values and its values.
    x_col: Option<u32>,
    y_col: u32,
    x: Option<Vec<Cell>>,
    values: Vec<Cell>,
}

fn letters(mut col: u32) -> String {
    let mut out = Vec::new();
    while col > 0 {
        out.push(b'A' + ((col - 1) % 26) as u8);
        col = (col - 1) / 26;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

fn formula(col: u32, first: usize, last: usize) -> String {
    let col = letters(col);
    if first == last {
        format!("'{SHEET}'!${col}${first}")
    } else {
        format!("'{SHEET}'!${col}${first}:${col}${last}")
    }
}

fn number_cells(values: &[Option<serde_json::Number>], count: usize) -> Vec<Cell> {
    (0..count)
        .map(|at| {
            values
                .get(at)
                .and_then(|value| value.as_ref()?.as_f64())
                .map_or(Cell::Missing, Cell::Number)
        })
        .collect()
}

/// The chart-side writer: the part's chart prefix and whether sequences
/// reference the rebuilt workbook or are literal.
struct Writer {
    c: String,
    book: bool,
}

impl Writer {
    fn el(&self, name: &str) -> String {
        format!("{}{name}", self.c)
    }

    fn points(&self, cells: &[Cell]) -> String {
        let mut out = format!(r#"<{} val="{}"/>"#, self.el("ptCount"), cells.len());
        for (idx, cell) in cells.iter().enumerate() {
            let text = match cell {
                Cell::Missing => continue,
                Cell::Number(value) => number(*value),
                Cell::Text(text) | Cell::Date(text) => escape_text(text),
            };
            out.push_str(&format!(
                r#"<{pt} idx="{idx}"><{v}>{text}</{v}></{pt}>"#,
                pt = self.el("pt"),
                v = self.el("v")
            ));
        }
        out
    }

    /// A sequence slot (`cat`, `val`, `xVal`, `yVal`): a reference with its
    /// cache over `col`'s rows from 2, or a literal. `format` is a kept
    /// `c:formatCode` element.
    fn slot(&self, slot: &str, numeric: bool, col: u32, cells: &[Cell], format: &str) -> String {
        let format = if numeric && format.is_empty() {
            format!("<{f}>General</{f}>", f = self.el("formatCode"))
        } else if numeric {
            format.to_owned()
        } else {
            String::new()
        };
        let points = self.points(cells);
        let inner = if self.book && !cells.is_empty() {
            let (reference, cache) = if numeric {
                ("numRef", "numCache")
            } else {
                ("strRef", "strCache")
            };
            format!(
                "<{r}><{f}>{}</{f}><{k}>{format}{points}</{k}></{r}>",
                escape_text(&formula(col, 2, cells.len() + 1)),
                r = self.el(reference),
                f = self.el("f"),
                k = self.el(cache),
            )
        } else {
            let literal = if numeric { "numLit" } else { "strLit" };
            format!("<{l}>{format}{points}</{l}>", l = self.el(literal))
        };
        format!("<{s}>{inner}</{s}>", s = self.el(slot))
    }

    fn tx(&self, name: &str, col: u32) -> String {
        let inner = if self.book {
            format!(
                "<{r}><{f}>{}</{f}><{k}>{}</{k}></{r}>",
                escape_text(&formula(col, 1, 1)),
                self.points(&[Cell::Text(name.to_owned())]),
                r = self.el("strRef"),
                f = self.el("f"),
                k = self.el("strCache"),
            )
        } else {
            format!("<{v}>{}</{v}>", escape_text(name), v = self.el("v"))
        };
        format!("<{t}>{inner}</{t}>", t = self.el("tx"))
    }
}

/// A sequence slot's kept `c:formatCode` element, if any.
fn format_code(bytes: &[u8], tree: &XmlTree, slot: Option<usize>) -> String {
    slot.and_then(|slot| held::within(tree, slot).find(|&at| tree.nodes[at].is(C, "formatCode")))
        .map_or_else(String::new, |at| {
            String::from_utf8_lossy(piece(bytes, tree, at)).into_owned()
        })
}

fn int(tree: &XmlTree, at: usize, name: &str) -> Option<u32> {
    tree.nodes[xml::child(tree, at, C, name)?]
        .attr("val")?
        .trim()
        .parse()
        .ok()
}

/// Rewrite a written chart's part to `payload`: each plot's series (kept
/// ones in place with their formatting, new ones plain), a single plot's
/// family, its axes when the family gains or loses them, and every
/// sequence as a reference into a rebuilt embedded workbook, or as a
/// literal when the chart has no workbook. The rewrite reads back as the
/// live data, and every cache equals its cells, or it refuses. The parts it
/// changed.
pub(super) fn chart(
    package: &mut Package,
    chart: &str,
    payload: &NodePayload,
) -> Result<Vec<String>, LiveError> {
    let NodePayload::Chart {
        family,
        categories,
        series,
        ..
    } = payload
    else {
        return Err(LiveError::Invalid(WRITTEN_FRAME));
    };
    let (bytes, tree) = xml::read(package, chart)?;
    let (area, plots) = held::plots(&tree).ok_or(LiveError::Invalid(WRITTEN_FRAME))?;
    let book = if tree.nodes.iter().any(|node| node.is(C, "f")) {
        // Every reference is series data and the workbook is the chart's own.
        chart_data(package, chart)?;
        let link = xml::child(&tree, 0, C, "externalData")
            .and_then(|data| tree.nodes[data].attr_ns(R, "id"))
            .ok_or(LiveError::Invalid(WRITTEN_FRAME))?;
        Some(
            package
                .relationships(chart)?
                .into_iter()
                .find(|rel| rel.id == link && !rel.external)
                .ok_or(LiveError::Invalid(WRITTEN_FRAME))?
                .target,
        )
    } else {
        None
    };
    let convert = plots.len() == 1 && plots[0].0 != *family;
    if convert && (plots[0].0 == ChartKind::Scatter || *family == ChartKind::Scatter) {
        return Err(LiveError::Invalid(WRITTEN_COMBO));
    }
    let kind_of = |plot: usize| if convert { *family } else { plots[plot].0 };
    let resolved = |line: &ChartSeries| {
        if convert {
            *family
        } else {
            line.family.unwrap_or(*family)
        }
    };
    // Each live series to a plot of its family: a plot keeps as many as it
    // held, in order, and the last plot of a family takes the rest.
    let held_sers: Vec<Vec<usize>> = plots
        .iter()
        .map(|&(_, at)| children(&tree, at, C, "ser").collect())
        .collect();
    let mut assigned: Vec<Vec<usize>> = vec![Vec::new(); plots.len()];
    for (index, line) in series.iter().enumerate() {
        let want = resolved(line);
        let candidates: Vec<usize> = (0..plots.len()).filter(|&p| kind_of(p) == want).collect();
        let last = *candidates.last().ok_or(LiveError::Invalid(WRITTEN_COMBO))?;
        let plot = candidates
            .iter()
            .copied()
            .find(|&p| assigned[p].len() < held_sers[p].len())
            .unwrap_or(last);
        assigned[plot].push(index);
    }
    // Categories stay numbers when the chart's were and every one reads
    // back as itself.
    let first_cat = held_sers
        .iter()
        .flatten()
        .find_map(|&ser| xml::child(&tree, ser, C, "cat"));
    let numeric_cats = first_cat
        .and_then(|slot| held::points(&tree, slot))
        .is_some_and(|points| points.numeric)
        && categories.iter().all(|category| {
            category
                .trim()
                .parse::<f64>()
                .is_ok_and(|value| held::label(&Cell::Number(value)) == *category)
        });
    let category_cells: Vec<Cell> = categories
        .iter()
        .map(|category| match category.parse::<f64>() {
            Ok(value) if numeric_cats => Cell::Number(value),
            _ if category.is_empty() => Cell::Missing,
            _ => Cell::Text(category.clone()),
        })
        .collect();
    // The workbook layout: categories in A, then each series' x column (a
    // scatter series') and values column.
    let mut next_col: u32 = if categories.is_empty() { 1 } else { 2 };
    let mut take = || {
        let col = next_col;
        next_col = next_col.saturating_add(1);
        col
    };
    let data: Vec<Data> = series
        .iter()
        .map(|line| {
            let scatter = resolved(line) == ChartKind::Scatter;
            let count = match (&line.x, scatter) {
                (Some(x), true) => x.len().max(line.values.len()),
                (None, true) => line.values.len(),
                _ if categories.is_empty() => line.values.len(),
                _ => categories.len(),
            };
            let x = line
                .x
                .as_ref()
                .filter(|_| scatter)
                .map(|x| number_cells(x, count));
            let x_col = x.as_ref().map(|_| take());
            Data {
                name: line.name.clone(),
                x_col,
                y_col: take(),
                x,
                values: number_cells(&line.values, count),
            }
        })
        .collect();
    let c = match xml::prefix(&tree.nodes[area]) {
        "" => String::new(),
        prefix => format!("{prefix}:"),
    };
    let writer = Writer {
        c,
        book: book.is_some(),
    };
    let mut next_idx = tree
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.is(C, "ser"))
        .filter_map(|(at, _)| int(&tree, at, "idx").max(int(&tree, at, "order")))
        .max()
        .map_or(0, |top| top.saturating_add(1));
    // New axis ids sit above every id the chart holds.
    let fresh_axis = tree
        .nodes
        .iter()
        .filter(|node| node.is(C, "axId"))
        .filter_map(|node| node.attr("val")?.trim().parse::<u32>().ok())
        .max()
        .map_or(1, |top| top.saturating_add(1));
    let mut plot_xml: Vec<Vec<u8>> = Vec::with_capacity(plots.len());
    for (plot, &(_, at)) in plots.iter().enumerate() {
        let kind = kind_of(plot);
        let mut sers = Vec::new();
        for (slot, &index) in assigned[plot].iter().enumerate() {
            let template = held_sers[plot].get(slot).copied();
            let (idx, order) = match template {
                Some(ser) => (
                    int(&tree, ser, "idx").unwrap_or(next_idx),
                    int(&tree, ser, "order").unwrap_or(next_idx),
                ),
                None => {
                    let fresh = next_idx;
                    next_idx = next_idx.saturating_add(1);
                    (fresh, fresh)
                }
            };
            let line = &data[index];
            let scatter = kind == ChartKind::Scatter;
            let (cat_name, val_name) = if scatter {
                ("xVal", "yVal")
            } else {
                ("cat", "val")
            };
            let cat_slot = template.and_then(|ser| xml::child(&tree, ser, C, cat_name));
            let val_slot = template.and_then(|ser| xml::child(&tree, ser, C, val_name));
            let cat_xml = match (&line.x, scatter) {
                (Some(x), true) => writer.slot(
                    cat_name,
                    true,
                    line.x_col.unwrap_or(1),
                    x,
                    &format_code(&bytes, &tree, cat_slot),
                ),
                (None, false) if !categories.is_empty() => writer.slot(
                    cat_name,
                    numeric_cats,
                    1,
                    &category_cells,
                    &format_code(&bytes, &tree, cat_slot.or(first_cat)),
                ),
                _ => String::new(),
            };
            let val_xml = writer.slot(
                val_name,
                true,
                line.y_col,
                &line.values,
                &format_code(&bytes, &tree, val_slot),
            );
            let tx = writer.tx(&line.name, line.y_col);
            let count = line.values.len();
            sers.extend(match template.filter(|_| !convert) {
                Some(ser) => kept_ser(
                    &bytes,
                    &tree,
                    ser,
                    (idx, order),
                    &writer,
                    [&tx, &cat_xml, &val_xml],
                    count,
                )?,
                None => {
                    let spr = template
                        .and_then(|ser| xml::child(&tree, ser, C, "spPr"))
                        .map_or_else(String::new, |at| {
                            String::from_utf8_lossy(piece(&bytes, &tree, at)).into_owned()
                        });
                    let smooth = if matches!(kind, ChartKind::Line | ChartKind::Scatter) {
                        format!(r#"<{} val="0"/>"#, writer.el("smooth"))
                    } else {
                        String::new()
                    };
                    format!(
                        r#"<{s}><{i} val="{idx}"/><{o} val="{order}"/>{tx}{spr}{cat_xml}{val_xml}{smooth}</{s}>"#,
                        s = writer.el("ser"),
                        i = writer.el("idx"),
                        o = writer.el("order"),
                    )
                    .into_bytes()
                }
            });
        }
        plot_xml.push(if convert {
            converted_plot(&bytes, &tree, at, kind, &writer, &sers, fresh_axis)
        } else {
            kept_plot(&bytes, &tree, at, &sers)
        });
    }
    // The plot area: plots rewritten; a converted plot's axes dropped when
    // its family has none, or added after it when it gains them.
    let (from, to) = (plots[0].0, *family);
    let mut out = xml::open_tag(&bytes, &tree.nodes[area]);
    for &child in &tree.nodes[area].children {
        let node = &tree.nodes[child];
        if let Some(plot) = plots.iter().position(|&(_, at)| at == child) {
            out.extend_from_slice(&plot_xml[plot]);
            if convert && to.has_axes() && !from.has_axes() {
                out.extend(axes(&writer, fresh_axis).into_bytes());
            }
        } else if convert
            && !to.has_axes()
            && node.namespace == C
            && matches!(node.name.as_str(), "catAx" | "valAx" | "dateAx" | "serAx")
        {
            continue;
        } else {
            out.extend_from_slice(piece(&bytes, &tree, child));
        }
    }
    out.extend(close(&tree.nodes[area]));
    let next = xml::splice(&bytes, vec![(tree.nodes[area].span.clone(), out)])?;
    package.replace_xml_part(chart, next)?;
    let mut changed = vec![chart.to_owned()];
    if let Some(book) = &book {
        let mut columns = Vec::new();
        let mut cells: Vec<Vec<Cell>> = Vec::new();
        let column = |name: String, kind| Column {
            name,
            kind,
            unit: None,
            format: None,
        };
        if !categories.is_empty() {
            let kind = if numeric_cats {
                ColumnKind::Number
            } else {
                ColumnKind::Text
            };
            columns.push(column(String::new(), kind));
            cells.push(category_cells.clone());
        }
        for line in &data {
            if let Some(x) = &line.x {
                columns.push(column(format!("{} (x)", line.name), ColumnKind::Number));
                cells.push(x.clone());
            }
            columns.push(column(line.name.clone(), ColumnKind::Number));
            cells.push(line.values.clone());
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
        let dataset = Dataset {
            id: String::new(),
            columns,
            rows,
            missing: None,
            sources: Vec::new(),
            merges: Vec::new(),
        };
        let workbook = chart_workbook(&dataset, SHEET, package.limits())?;
        package.replace_nested_package(book, workbook)?;
        changed.push(book.clone());
        let read = chart_data(package, chart)?;
        let agree = read
            .series
            .iter()
            .flat_map(|line| [&line.name, &line.categories, &line.values])
            .flatten()
            .all(|sequence| {
                sequence
                    .cache
                    .iter()
                    .map(held::label)
                    .eq(sequence.workbook.iter().map(held::label))
            });
        if !agree {
            return Err(LiveError::Invalid(READ_BACK));
        }
    }
    let read = held::chart(package, chart).ok_or(LiveError::Invalid(READ_BACK))?;
    if !same_data(&read, payload) {
        return Err(LiveError::Invalid(READ_BACK));
    }
    Ok(changed)
}

/// A kept series with its sequences replaced: `idx` and `order` as held,
/// `tx` (inserted after `order` when it had none), the category (or x)
/// slot before the value slot, and data points and labels past the new
/// point count dropped. Everything else keeps its bytes.
fn kept_ser(
    bytes: &[u8],
    tree: &XmlTree,
    ser: usize,
    (idx, order): (u32, u32),
    writer: &Writer,
    [tx, cat, val]: [&str; 3],
    count: usize,
) -> Result<Vec<u8>, LiveError> {
    let mut out = xml::open_tag(bytes, &tree.nodes[ser]);
    let (mut named, mut cat_done, mut data_done) = (false, false, false);
    let push = |out: &mut Vec<u8>, text: &str| out.extend_from_slice(text.as_bytes());
    for &child in &tree.nodes[ser].children {
        let node = &tree.nodes[child];
        if node.namespace != C {
            out.extend_from_slice(piece(bytes, tree, child));
            continue;
        }
        match node.name.as_str() {
            "idx" => push(&mut out, &format!(r#"<{} val="{idx}"/>"#, writer.el("idx"))),
            "order" => {
                push(
                    &mut out,
                    &format!(r#"<{} val="{order}"/>"#, writer.el("order")),
                );
                if xml::child(tree, ser, C, "tx").is_none() {
                    push(&mut out, tx);
                    named = true;
                }
            }
            "tx" if !named => {
                push(&mut out, tx);
                named = true;
            }
            "tx" => {}
            "cat" | "xVal" => {
                push(&mut out, cat);
                cat_done = true;
            }
            "val" | "yVal" => {
                if !cat_done {
                    push(&mut out, cat);
                    cat_done = true;
                }
                push(&mut out, val);
                data_done = true;
            }
            "dPt" => {
                if int(tree, child, "idx").is_some_and(|point| (point as usize) < count) {
                    out.extend_from_slice(piece(bytes, tree, child));
                }
            }
            "dLbls" if !node.empty => {
                out.extend(xml::open_tag(bytes, node));
                for &label in &node.children {
                    let kept = !tree.nodes[label].is(C, "dLbl")
                        || int(tree, label, "idx").is_some_and(|point| (point as usize) < count);
                    if kept {
                        out.extend_from_slice(piece(bytes, tree, label));
                    }
                }
                out.extend(close(node));
            }
            "shape" | "smooth" | "extLst" | "bubbleSize" | "bubble3D" if !data_done => {
                if !cat_done {
                    push(&mut out, cat);
                    cat_done = true;
                }
                push(&mut out, val);
                data_done = true;
                out.extend_from_slice(piece(bytes, tree, child));
            }
            _ => out.extend_from_slice(piece(bytes, tree, child)),
        }
    }
    if !data_done {
        if !cat_done {
            push(&mut out, cat);
        }
        push(&mut out, val);
    }
    out.extend(close(&tree.nodes[ser]));
    Ok(out)
}

/// A kept plot with its series replaced where they stood.
fn kept_plot(bytes: &[u8], tree: &XmlTree, plot: usize, sers: &[u8]) -> Vec<u8> {
    const AFTER: &[&str] = &[
        "dLbls",
        "gapWidth",
        "overlap",
        "serLines",
        "axId",
        "dropLines",
        "hiLowLines",
        "upDownBars",
        "marker",
        "smooth",
        "firstSliceAng",
        "holeSize",
        "extLst",
    ];
    let mut out = xml::open_tag(bytes, &tree.nodes[plot]);
    let mut placed = false;
    for &child in &tree.nodes[plot].children {
        let node = &tree.nodes[child];
        if node.is(C, "ser") {
            if !placed {
                out.extend_from_slice(sers);
                placed = true;
            }
            continue;
        }
        if !placed && node.namespace == C && AFTER.contains(&node.name.as_str()) {
            out.extend_from_slice(sers);
            placed = true;
        }
        out.extend_from_slice(piece(bytes, tree, child));
    }
    if !placed {
        out.extend_from_slice(sers);
    }
    out.extend(close(&tree.nodes[plot]));
    out
}

/// A single plot written as another family: that family's required
/// elements, the series, and its axis ids (kept when both families plot on
/// axes, new when it gains them).
fn converted_plot(
    bytes: &[u8],
    tree: &XmlTree,
    plot: usize,
    kind: ChartKind,
    writer: &Writer,
    sers: &[u8],
    fresh: u32,
) -> Vec<u8> {
    let el = |name: &str| writer.el(name);
    let flag = |name: &str, value: &str| format!(r#"<{} val="{value}"/>"#, el(name));
    let (head, tail) = match kind {
        ChartKind::Bar => (
            format!(
                "{}{}{}",
                flag("barDir", "col"),
                flag("grouping", "clustered"),
                flag("varyColors", "0")
            ),
            flag("gapWidth", "150"),
        ),
        ChartKind::Line => (
            format!(
                "{}{}",
                flag("grouping", "standard"),
                flag("varyColors", "0")
            ),
            flag("marker", "1"),
        ),
        ChartKind::Area => (
            format!(
                "{}{}",
                flag("grouping", "standard"),
                flag("varyColors", "0")
            ),
            String::new(),
        ),
        ChartKind::Radar => (
            format!(
                "{}{}",
                flag("radarStyle", "marker"),
                flag("varyColors", "0")
            ),
            String::new(),
        ),
        ChartKind::Scatter => (
            format!(
                "{}{}",
                flag("scatterStyle", "lineMarker"),
                flag("varyColors", "0")
            ),
            String::new(),
        ),
        ChartKind::Pie => (flag("varyColors", "1"), flag("firstSliceAng", "0")),
        ChartKind::Doughnut => (
            flag("varyColors", "1"),
            format!("{}{}", flag("firstSliceAng", "0"), flag("holeSize", "50")),
        ),
    };
    let kept_ids: Vec<usize> = children(tree, plot, C, "axId").collect();
    let ids = if !kind.has_axes() {
        String::new()
    } else if kept_ids.is_empty() {
        format!(
            "{}{}",
            flag("axId", &fresh.to_string()),
            flag("axId", &fresh.saturating_add(1).to_string())
        )
    } else {
        kept_ids
            .iter()
            .map(|&at| String::from_utf8_lossy(piece(bytes, tree, at)).into_owned())
            .collect()
    };
    let name = el(kind.element());
    format!("<{name}>{head}")
        .into_bytes()
        .into_iter()
        .chain(sers.iter().copied())
        .chain(format!("{tail}{ids}</{name}>").into_bytes())
        .collect()
}

/// A category and a value axis for a plot that gains axes, crossing each
/// other, under the ids [`converted_plot`] gave it.
fn axes(writer: &Writer, fresh: u32) -> String {
    let (cat, val) = (fresh, fresh.saturating_add(1));
    let el = |name: &str| writer.el(name);
    let flag = |name: &str, value: &str| format!(r#"<{} val="{value}"/>"#, el(name));
    let scaling = format!(
        "<{s}>{}</{s}>",
        flag("orientation", "minMax"),
        s = el("scaling")
    );
    let format = format!(
        r#"<{} formatCode="General" sourceLinked="1"/>"#,
        el("numFmt")
    );
    format!(
        "<{ca}>{}{scaling}{}{}{format}{}{}{}{}{}{}</{ca}><{va}>{}{scaling}{}{}<{grid}/>{format}{}{}{}{}</{va}>",
        flag("axId", &cat.to_string()),
        flag("delete", "0"),
        flag("axPos", "b"),
        flag("tickLblPos", "nextTo"),
        flag("crossAx", &val.to_string()),
        flag("crosses", "autoZero"),
        flag("auto", "1"),
        flag("lblAlgn", "ctr"),
        flag("lblOffset", "100"),
        flag("axId", &val.to_string()),
        flag("delete", "0"),
        flag("axPos", "l"),
        flag("tickLblPos", "nextTo"),
        flag("crossAx", &cat.to_string()),
        flag("crosses", "autoZero"),
        flag("crossBetween", "between"),
        ca = el("catAx"),
        va = el("valAx"),
        grid = el("majorGridlines"),
    )
}

/// The same-length sequence writes that make a workbook chart read as
/// `wanted` without a rewrite: each series' name, categories (or x values)
/// and values that differ, for the checked chart writer. `None` when the
/// chart changes shape, or a sequence that changes is literal or changes
/// length.
pub(super) fn plan(
    package: &Package,
    chart: &str,
    have: &NodePayload,
    wanted: &NodePayload,
) -> Option<Vec<(usize, Target, Vec<Cell>)>> {
    let (
        NodePayload::Chart {
            family,
            categories: held_categories,
            series: held_series,
            ..
        },
        NodePayload::Chart {
            family: want_family,
            categories,
            series,
            ..
        },
    ) = (have, wanted)
    else {
        return None;
    };
    if family != want_family
        || held_series.len() != series.len()
        || held_series.iter().zip(series).any(|(was, now)| {
            was.family.unwrap_or(*family) != now.family.unwrap_or(*want_family)
                || was.x.is_some() != now.x.is_some()
        })
    {
        return None;
    }
    let data = chart_data(package, chart).ok()?;
    let mut writes = Vec::new();
    for (index, (was, now)) in held_series.iter().zip(series).enumerate() {
        let line = data.series.get(index)?;
        if was.name != now.name {
            line.name.as_ref().filter(|name| name.cache.len() == 1)?;
            writes.push((index, Target::Name, vec![Cell::Text(now.name.clone())]));
        }
        if let Some(x) = &now.x {
            let held = line.categories.as_ref()?;
            if x.len() > held.cache.len() {
                return None;
            }
            let cells = number_cells(x, held.cache.len());
            if held.cache != cells {
                writes.push((index, Target::Categories, cells));
            }
        } else if now.family.unwrap_or(*want_family) != ChartKind::Scatter
            && held_categories != categories
        {
            let held = line.categories.as_ref()?;
            if held.cache.len() != categories.len() {
                return None;
            }
            // A number category stays a number.
            let cells = categories
                .iter()
                .zip(&held.cache)
                .map(|(category, cell)| match cell {
                    Cell::Number(_) => category
                        .parse()
                        .map_or_else(|_| Cell::Text(category.clone()), Cell::Number),
                    _ => Cell::Text(category.clone()),
                })
                .collect();
            writes.push((index, Target::Categories, cells));
        }
        let len = line
            .values
            .as_ref()
            .map_or(was.values.len(), |values| values.cache.len());
        if now.values.len() > len {
            return None;
        }
        let cells = number_cells(&now.values, len);
        match &line.values {
            Some(values) if values.cache != cells => {
                writes.push((index, Target::Values, cells));
            }
            Some(_) => {}
            None if number_cells(&was.values, len) == cells => {}
            None => return None,
        }
    }
    Some(writes)
}

/// `read` reads as `wanted`: the same family, categories and series names,
/// each series in the same plot family, and the same values (as numbers;
/// a shorter wanted sequence ends in missing points).
pub(super) fn same_data(read: &NodePayload, wanted: &NodePayload) -> bool {
    let (
        NodePayload::Chart {
            family,
            categories,
            series,
            ..
        },
        NodePayload::Chart {
            family: want_family,
            categories: want_categories,
            series: want_series,
            ..
        },
    ) = (read, wanted)
    else {
        return false;
    };
    let padded = |read: &[Option<serde_json::Number>], wanted: &[Option<serde_json::Number>]| {
        let number = |value: &Option<serde_json::Number>| value.as_ref().and_then(|n| n.as_f64());
        read.len() >= wanted.len()
            && read.iter().zip(wanted).all(|(a, b)| number(a) == number(b))
            && read[wanted.len()..].iter().all(Option::is_none)
    };
    family == want_family
        && categories == want_categories
        && series.len() == want_series.len()
        && series.iter().zip(want_series).all(|(a, b)| {
            a.name == b.name
                && a.family.unwrap_or(*family) == b.family.unwrap_or(*want_family)
                && padded(a.values.as_slice(), b.values.as_slice())
                && match (&a.x, &b.x) {
                    (Some(a), Some(b)) => padded(a.as_slice(), b.as_slice()),
                    (None, None) => true,
                    _ => false,
                }
        })
}
