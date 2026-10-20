//! Shape changes to a written table or chart at export (OF-510). A table's
//! rows and columns are rewritten over its grid by identity, and its frame
//! takes the grid's size; a chart's plots, series and categories are
//! rewritten over its part and its caches, and its own embedded workbook is
//! edited in place, only the cells its series read written (ARCH-0077: caches and
//! workbooks are projections of one dataset); a workbook that cannot be
//! edited so is rebuilt from the live data, the reason named. A chart
//! changes type as PowerPoint's Change Chart Type does, for the chart or
//! one series: between a category and a scatter family too, and a family
//! the chart has no plot for gets one. What the live model does not name
//! keeps its bytes: a kept row's, column's or cell's properties, a kept
//! series' formatting, the chart's titles, axes and legend, and the
//! workbook's other cells; a new series is formatted after a held one.

mod layout;
mod series;
mod table;
mod workbook;

pub(super) use layout::plot_plan;
pub(super) use table::table;

use super::LiveError;
use super::conversion::{Conversion, RebuildReason};
use super::convert;
use super::held::{self, C, children};
use super::pptx::{ChartKind, ChartSource, NodePayload, WRITTEN_FRAME};
use crate::design_plan::{Cell, Column, ColumnKind, Dataset};
use crate::edit::xml::{self, P, R};
use crate::native_patch::{Target, chart_data, chart_workbook, number};
use crate::ooxml::{Node, XmlTree, escape_text};
use crate::retained_opc::Package;
use layout::{Data, Layout, Wanted, first_category, layout, number_cells, wanted};
use std::collections::{BTreeMap, BTreeSet};

/// The one sheet of a rewritten chart's embedded workbook.
const SHEET: &str = "Sheet1";
/// A rewrite that does not read back as the live data refuses.
const READ_BACK: &str = "a rewritten chart does not read back as the live data";

fn piece<'b>(bytes: &'b [u8], tree: &XmlTree, at: usize) -> &'b [u8] {
    &bytes[tree.nodes[at].span.clone()]
}

fn close(node: &Node) -> Vec<u8> {
    format!("</{}>", node.qualified).into_bytes()
}

/// The graphic frame with this native id in a slide part.
pub(super) fn frame_of(tree: &XmlTree, native: u32) -> Option<usize> {
    let id = native.to_string();
    (0..tree.nodes.len()).find(|&at| {
        tree.nodes[at].is(P, "graphicFrame")
            && xml::path(tree, at, &[(P, "nvGraphicFramePr"), (P, "cNvPr")])
                .is_some_and(|c_nv_pr| tree.nodes[c_nv_pr].attr("id") == Some(id.as_str()))
    })
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

/// The chart-side writer: the part's chart prefix.
struct Writer {
    c: String,
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

    /// A sequence slot (`cat`, `val`, `xVal`, `yVal`): `reference` with its
    /// cache over `cells`, or a literal when it has no reference or no
    /// cells. `format` is a kept `c:formatCode` element.
    fn slot(
        &self,
        slot: &str,
        numeric: bool,
        reference: Option<&str>,
        cells: &[Cell],
        format: &str,
    ) -> String {
        let format = if numeric && format.is_empty() {
            format!("<{f}>General</{f}>", f = self.el("formatCode"))
        } else if numeric {
            format.to_owned()
        } else {
            String::new()
        };
        let points = self.points(cells);
        let inner = match reference.filter(|_| !cells.is_empty()) {
            Some(reference) => {
                let (kind, cache) = if numeric {
                    ("numRef", "numCache")
                } else {
                    ("strRef", "strCache")
                };
                format!(
                    "<{r}><{f}>{}</{f}><{k}>{format}{points}</{k}></{r}>",
                    escape_text(reference),
                    r = self.el(kind),
                    f = self.el("f"),
                    k = self.el(cache),
                )
            }
            None => {
                let literal = if numeric { "numLit" } else { "strLit" };
                format!("<{l}>{format}{points}</{l}>", l = self.el(literal))
            }
        };
        format!("<{s}>{inner}</{s}>", s = self.el(slot))
    }

    /// A series name: `reference` with its cache, or a literal.
    fn tx(&self, name: &str, reference: Option<&str>) -> String {
        let inner = match reference {
            Some(reference) => format!(
                "<{r}><{f}>{}</{f}><{k}>{}</{k}></{r}>",
                escape_text(reference),
                self.points(&[Cell::Text(name.to_owned())]),
                r = self.el("strRef"),
                f = self.el("f"),
                k = self.el("strCache"),
            ),
            None => format!("<{v}>{}</{v}>", escape_text(name), v = self.el("v")),
        };
        format!("<{t}>{inner}</{t}>", t = self.el("tx"))
    }
}

/// The references one rewritten series writes: its name, its categories
/// or x values, its values. `None` writes a literal.
#[derive(Debug, Clone, Default)]
struct Refs {
    name: Option<String>,
    first: Option<String>,
    values: Option<String>,
}

impl Refs {
    /// A series' references into a rebuilt workbook: its name in row 1 over
    /// its values column, and its x values column (a scatter series') or
    /// the categories in A.
    fn rebuilt(line: &Data, categories: usize) -> Self {
        let first = match (&line.x, line.x_col) {
            (Some(x), Some(col)) => Some(formula(col, 2, x.len() + 1)),
            _ if categories > 0 => Some(formula(1, 2, categories + 1)),
            _ => None,
        };
        Self {
            name: Some(formula(line.y_col, 1, 1)),
            first,
            values: Some(formula(line.y_col, 2, line.values.len() + 1)),
        }
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

/// The family a live-born chart's native seed is written as before the
/// rewrite gives the chart its own: a bar or line chart's own, a pie's when
/// it has one series, a bar chart's otherwise.
pub(super) fn seed_family(payload: &NodePayload) -> ChartKind {
    match payload {
        NodePayload::Chart {
            family: family @ (ChartKind::Bar | ChartKind::Line),
            ..
        } => *family,
        NodePayload::Chart {
            family: ChartKind::Pie,
            series,
            ..
        } if series.len() == 1 => ChartKind::Pie,
        _ => ChartKind::Bar,
    }
}

/// The chart's own embedded workbook, when every reference the chart holds
/// is series data in it.
fn own_workbook(
    package: &Package,
    chart: &str,
    tree: &XmlTree,
) -> Result<Option<String>, LiveError> {
    if !tree.nodes.iter().any(|node| node.is(C, "f")) || chart_data(package, chart).is_err() {
        return Ok(None);
    }
    let Some(link) =
        xml::child(tree, 0, C, "externalData").and_then(|data| tree.nodes[data].attr_ns(R, "id"))
    else {
        return Ok(None);
    };
    Ok(package
        .relationships(chart)?
        .into_iter()
        .find(|rel| rel.id == link && !rel.external)
        .map(|rel| rel.target))
}

fn is_axis(node: &Node) -> bool {
    node.namespace == C && matches!(node.name.as_str(), "catAx" | "valAx" | "dateAx" | "serAx")
}

/// The rebuilt workbook's one sheet: categories in A, then each series' x
/// column (a scatter series') and values column, under a header row.
fn workbook_dataset(
    categories: &[String],
    numeric_cats: bool,
    category_cells: &[Cell],
    data: &[Data],
) -> Dataset {
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
        cells.push(category_cells.to_vec());
    }
    for line in data {
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
    Dataset {
        id: String::new(),
        columns,
        rows,
        missing: None,
        sources: Vec::new(),
        merges: Vec::new(),
    }
}

/// Rewrite a written chart's part to `payload`: its plots as [`plot_plan`]
/// lays them out (a kept plot's series in place with their formatting, a
/// new series formatted after a held one as [`series::fresh`] writes it, a
/// converted or new plot in its family's defaults), its axes as the plots
/// need them (kept, shared, turned between category and value axes when a
/// plot changes between a category and a scatter family, added, or
/// dropped), and every sequence as a reference into the chart's own
/// embedded workbook. That workbook is edited in place where it can be:
/// only the cells the series read are written, and its other sheets,
/// formulas, formats, names and tables keep their bytes
/// ([`workbook::in_place`]). Where it cannot be, it is rebuilt from the
/// live data as before, and `done` names why
/// ([`Conversion::WorkbookRebuilt`]). A chart whose data lived elsewhere (a
/// link, a shared workbook) gets a new embedded workbook, as PowerPoint's
/// Edit Data does; so does a literal chart the payload moves to a
/// workbook, and any other literal chart stays literal. The rewrite reads
/// back as the live data, and every cache equals its cells, or it refuses.
/// The parts it changed; `done` gets what it did PowerPoint's way.
pub(super) fn chart(
    package: &mut Package,
    chart: &str,
    payload: &NodePayload,
    done: &mut Vec<Conversion>,
) -> Result<Vec<String>, LiveError> {
    let (part, reason) = match workbook::original(package, chart, payload)? {
        workbook::Original::Absent => return rewrite(package, chart, payload, done, None),
        workbook::Original::Replaced(part, reason) => (part, reason),
        workbook::Original::Own(part) => {
            // The edit runs on a copy: whatever stops it, the rebuild below
            // starts from the package as it was.
            let mut candidate = package.clone();
            let mut kept = Vec::new();
            let reason = match workbook::in_place(&candidate, chart, &part, payload) {
                Ok(edit) => match rewrite(&mut candidate, chart, payload, &mut kept, Some(edit)) {
                    Ok(changed) => {
                        *package = candidate;
                        done.extend(kept);
                        return Ok(changed);
                    }
                    Err(_) => RebuildReason::ReadBack,
                },
                Err(reason) => reason,
            };
            (part, reason)
        }
    };
    let changed = rewrite(package, chart, payload, done, None)?;
    done.push(Conversion::WorkbookRebuilt { part, reason });
    Ok(changed)
}

/// Rewrite a live-born chart's native seed to `payload`, its workbook
/// rebuilt from the live data: the seed's is the engine's own, holding
/// nothing a deck kept.
pub(super) fn reseed(
    package: &mut Package,
    chart: &str,
    payload: &NodePayload,
) -> Result<Vec<String>, LiveError> {
    rewrite(package, chart, payload, &mut Vec::new(), None)
}

/// [`chart`]'s rewrite: into the chart's own workbook as `in_place` edits
/// it, or, without an edit, into one rebuilt from the live data.
fn rewrite(
    package: &mut Package,
    chart: &str,
    payload: &NodePayload,
    done: &mut Vec<Conversion>,
    in_place: Option<workbook::InPlace>,
) -> Result<Vec<String>, LiveError> {
    let NodePayload::Chart {
        family,
        categories,
        series,
        source,
    } = payload
    else {
        return Err(LiveError::Invalid(WRITTEN_FRAME));
    };
    let (_, first) = xml::read(package, chart)?;
    let Wanted {
        resolved,
        numeric_cats,
        category_cells,
        data,
    } = wanted(&first, *family, categories, series);
    let dataset = workbook_dataset(categories, numeric_cats, &category_cells, &data);
    let mut changed = vec![chart.to_owned()];
    let book = match &in_place {
        Some(edit) => Some(edit.part.clone()),
        None => match own_workbook(package, chart, &first)? {
            Some(book) => Some(book),
            None if *source == ChartSource::Literal => None,
            None => {
                let workbook = chart_workbook(&dataset, SHEET, package.limits())?;
                let (book, embedded) = convert::embed_workbook(package, chart, workbook)?;
                done.extend(embedded);
                Some(book)
            }
        },
    };
    let (bytes, tree) = xml::read(package, chart)?;
    let Layout {
        area,
        plots,
        targets,
        assigned,
        seats,
    } = layout(&tree, *family, &resolved).ok_or(LiveError::Invalid(WRITTEN_FRAME))?;
    for target in &targets {
        match target.held {
            Some(at) if plots[at].0 != target.kind => done.push(Conversion::ChartTypeChanged {
                from: plots[at].0,
                to: target.kind,
            }),
            Some(_) => {}
            None => done.push(Conversion::PlotAdded {
                family: target.kind,
            }),
        }
    }
    for (at, &(kind, _)) in plots.iter().enumerate() {
        if !targets.iter().any(|target| target.held == Some(at)) {
            done.push(Conversion::PlotDropped { family: kind });
        }
    }
    let first_cat = first_category(&tree);
    let c = match xml::prefix(&tree.nodes[area]) {
        "" => String::new(),
        prefix => format!("{prefix}:"),
    };
    let writer = Writer { c };
    let mut next_idx = tree
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.is(C, "ser"))
        .filter_map(|(at, _)| int(&tree, at, "idx").max(int(&tree, at, "order")))
        .max()
        .map_or(0, |top| top.saturating_add(1));
    // The axes each plot plots on: a held plot's own, another plot's of the
    // same kind, or a new pair, each id above every id the chart holds. A
    // held x axis turns between a category and a value axis with its plot.
    let held_axes: Vec<(u32, usize)> = tree.nodes[area]
        .children
        .iter()
        .copied()
        .filter(|&at| is_axis(&tree.nodes[at]))
        .filter_map(|at| Some((int(&tree, at, "axId")?, at)))
        .collect();
    let mut fresh = tree
        .nodes
        .iter()
        .filter(|node| node.is(C, "axId"))
        .filter_map(|node| node.attr("val")?.trim().parse::<u32>().ok())
        .max()
        .map_or(1, |top| top.saturating_add(1));
    let mut value_x: BTreeMap<u32, bool> = held_axes
        .iter()
        .map(|&(id, at)| (id, tree.nodes[at].name == "valAx"))
        .collect();
    let mut retyped: BTreeMap<u32, bool> = BTreeMap::new();
    let mut new_axes = String::new();
    let mut ids_of: Vec<Vec<u32>> = Vec::with_capacity(targets.len());
    for target in &targets {
        let wants_value = target.kind == ChartKind::Scatter;
        let kept: Vec<u32> = target
            .held
            .filter(|&at| plots[at].0.has_axes())
            .map(|at| {
                children(&tree, plots[at].1, C, "axId")
                    .filter_map(|id| tree.nodes[id].attr("val")?.trim().parse().ok())
                    .collect()
            })
            .unwrap_or_default();
        let shared = ids_of
            .iter()
            .find(|ids| {
                ids.len() >= 2 && value_x.get(&ids[0]).copied().unwrap_or(false) == wants_value
            })
            .cloned();
        let ids = if !target.kind.has_axes() {
            Vec::new()
        } else if let Some(&x) = kept.first() {
            if value_x.get(&x).copied().unwrap_or(false) != wants_value {
                retyped.insert(x, wants_value);
                value_x.insert(x, wants_value);
            }
            kept
        } else if let Some(ids) = shared {
            ids
        } else {
            let secondary = ids_of.iter().any(|ids| !ids.is_empty());
            new_axes.push_str(&axes(&writer, fresh, wants_value, secondary));
            value_x.insert(fresh, wants_value);
            let ids = vec![fresh, fresh.saturating_add(1)];
            fresh = fresh.saturating_add(2);
            ids
        };
        ids_of.push(ids);
    }
    let mut plot_xml: Vec<Vec<u8>> = Vec::with_capacity(targets.len());
    for (at_target, target) in targets.iter().enumerate() {
        let kind = target.kind;
        let kept = target.held.filter(|&at| plots[at].0 == kind);
        let mut sers = Vec::new();
        for &index in &assigned[at_target] {
            let seat = seats[index];
            let (idx, order) = match seat.held {
                Some(ser) => (
                    int(&tree, ser, "idx").unwrap_or(next_idx),
                    int(&tree, ser, "order").unwrap_or(next_idx),
                ),
                None => {
                    let minted = next_idx;
                    next_idx = next_idx.saturating_add(1);
                    (minted, minted)
                }
            };
            let line = &data[index];
            let rebuilt;
            let refs = match &in_place {
                Some(edit) => &edit.refs[index],
                None => {
                    rebuilt = if book.is_some() {
                        Refs::rebuilt(line, categories.len())
                    } else {
                        Refs::default()
                    };
                    &rebuilt
                }
            };
            let scatter = kind == ChartKind::Scatter;
            let (cat_name, val_name) = if scatter {
                ("xVal", "yVal")
            } else {
                ("cat", "val")
            };
            let cat_slot = seat
                .template
                .and_then(|ser| xml::child(&tree, ser, C, cat_name));
            let val_slot = seat
                .template
                .and_then(|ser| xml::child(&tree, ser, C, val_name));
            let cat_xml = match (&line.x, scatter) {
                (Some(x), true) => writer.slot(
                    cat_name,
                    true,
                    refs.first.as_deref(),
                    x,
                    &format_code(&bytes, &tree, cat_slot),
                ),
                (None, false) if !categories.is_empty() => writer.slot(
                    cat_name,
                    numeric_cats,
                    refs.first.as_deref(),
                    &category_cells,
                    &format_code(&bytes, &tree, cat_slot.or(first_cat)),
                ),
                _ => String::new(),
            };
            let val_xml = writer.slot(
                val_name,
                true,
                refs.values.as_deref(),
                &line.values,
                &format_code(&bytes, &tree, val_slot),
            );
            let tx = writer.tx(&line.name, refs.name.as_deref());
            let count = line.values.len();
            sers.extend(match seat.held.filter(|_| kept.is_some()) {
                Some(ser) => kept_ser(
                    &bytes,
                    &tree,
                    ser,
                    (idx, order),
                    &writer,
                    [&tx, &cat_xml, &val_xml],
                    count,
                )?,
                None => series::fresh(
                    &bytes,
                    &tree,
                    seat.template,
                    kind,
                    &writer,
                    (idx, order),
                    [&tx, &cat_xml, &val_xml],
                ),
            });
        }
        plot_xml.push(match kept {
            Some(at) => kept_plot(&bytes, &tree, plots[at].1, &sers),
            None => fresh_plot(kind, &writer, &sers, &ids_of[at_target]),
        });
    }
    // The axes: each held axis a plot still plots on (turned where its plot
    // changed kind), then the new ones.
    let referenced: BTreeSet<u32> = ids_of.iter().flatten().copied().collect();
    let mut axes_xml = Vec::new();
    for &(id, at) in &held_axes {
        if !referenced.contains(&id) {
            continue;
        }
        match retyped.get(&id) {
            Some(&value) => axes_xml.extend(retyped_axis(&bytes, &tree, at, value, &writer)),
            None => axes_xml.extend_from_slice(piece(&bytes, &tree, at)),
        }
    }
    axes_xml.extend(new_axes.into_bytes());
    // The plot area: the plots where the held ones stood, then the axes
    // before anything that follows them.
    let held_at: BTreeSet<usize> = plots.iter().map(|&(_, at)| at).collect();
    let mut out = xml::open_tag(&bytes, &tree.nodes[area]);
    let mut plots_xml = Some(plot_xml.concat());
    let mut axes_xml = Some(axes_xml);
    for &child in &tree.nodes[area].children {
        let node = &tree.nodes[child];
        if held_at.contains(&child) {
            if let Some(xml) = plots_xml.take() {
                out.extend(xml);
            }
            continue;
        }
        let after =
            node.namespace == C && matches!(node.name.as_str(), "dTable" | "spPr" | "extLst");
        if is_axis(node) || (after && plots_xml.is_none()) {
            if let Some(xml) = axes_xml.take() {
                out.extend(xml);
            }
            if is_axis(node) {
                continue;
            }
        }
        out.extend_from_slice(piece(&bytes, &tree, child));
    }
    if let Some(xml) = axes_xml.take() {
        out.extend(xml);
    }
    out.extend(close(&tree.nodes[area]));
    let next = xml::splice(&bytes, vec![(tree.nodes[area].span.clone(), out)])?;
    package.replace_xml_part(chart, next)?;
    if let Some(book) = &book {
        let (workbook, notes) = match in_place {
            Some(edit) => (edit.bytes, edit.notes),
            None => (
                Some(chart_workbook(&dataset, SHEET, package.limits())?),
                Vec::new(),
            ),
        };
        if let Some(workbook) = workbook {
            package.replace_nested_package(book, workbook)?;
            changed.push(book.clone());
        }
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
        done.extend(notes);
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

/// A plot written fresh in `kind`: that family's required elements, the
/// series, and the axis ids it plots on.
fn fresh_plot(kind: ChartKind, writer: &Writer, sers: &[u8], ids: &[u32]) -> Vec<u8> {
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
    let ids: String = ids.iter().map(|id| flag("axId", &id.to_string())).collect();
    let name = el(kind.element());
    format!("<{name}>{head}")
        .into_bytes()
        .into_iter()
        .chain(sers.iter().copied())
        .chain(format!("{tail}{ids}</{name}>").into_bytes())
        .collect()
}

/// A held x axis turned into the other kind of axis, a value axis
/// (`value`) for a scatter plot or a category axis for a category plot, as
/// a chart type change between them turns it: the elements both kinds hold
/// keep their bytes, then that kind's own defaults follow.
fn retyped_axis(
    bytes: &[u8],
    tree: &XmlTree,
    axis: usize,
    value: bool,
    writer: &Writer,
) -> Vec<u8> {
    const SHARED: &[&str] = &[
        "axId",
        "scaling",
        "delete",
        "axPos",
        "majorGridlines",
        "minorGridlines",
        "title",
        "numFmt",
        "majorTickMark",
        "minorTickMark",
        "tickLblPos",
        "spPr",
        "txPr",
        "crossAx",
        "crosses",
        "crossesAt",
    ];
    let flag = |name: &str, val: &str| format!(r#"<{} val="{val}"/>"#, writer.el(name));
    let name = writer.el(if value { "valAx" } else { "catAx" });
    let mut out = format!("<{name}>").into_bytes();
    for &child in &tree.nodes[axis].children {
        let node = &tree.nodes[child];
        if node.namespace == C && SHARED.contains(&node.name.as_str()) {
            out.extend_from_slice(piece(bytes, tree, child));
        }
    }
    let tail = if value {
        flag("crossBetween", "midCat")
    } else {
        format!(
            "{}{}{}{}",
            flag("auto", "1"),
            flag("lblAlgn", "ctr"),
            flag("lblOffset", "100"),
            flag("noMultiLvlLbl", "0")
        )
    };
    out.extend(format!("{tail}</{name}>").into_bytes());
    out
}

/// A new pair of axes under ids `fresh` and `fresh + 1`, crossing each
/// other: an x axis (a value axis for a scatter plot, `value`, else a
/// category axis) and a value axis. A `secondary` pair, beside a plot that
/// already has axes, hides its x axis and puts its value axis on the right.
fn axes(writer: &Writer, fresh: u32, value: bool, secondary: bool) -> String {
    let (x, y) = (fresh, fresh.saturating_add(1));
    let el = |name: &str| writer.el(name);
    let flag = |name: &str, val: &str| format!(r#"<{} val="{val}"/>"#, el(name));
    let scaling = format!(
        "<{s}>{}</{s}>",
        flag("orientation", "minMax"),
        s = el("scaling")
    );
    let format = format!(
        r#"<{} formatCode="General" sourceLinked="1"/>"#,
        el("numFmt")
    );
    let common =
        |id: u32, deleted: &str, position: &str, gridlines: &str, cross: u32, crosses: &str| {
            format!(
                "{}{scaling}{}{}{gridlines}{format}{}{}{}",
                flag("axId", &id.to_string()),
                flag("delete", deleted),
                flag("axPos", position),
                flag("tickLblPos", "nextTo"),
                flag("crossAx", &cross.to_string()),
                flag("crosses", crosses),
            )
        };
    let (hidden, side, crosses) = if secondary {
        ("1", "r", "max")
    } else {
        ("0", "l", "autoZero")
    };
    let x_axis = if value {
        format!(
            "<{va}>{}{}</{va}>",
            common(x, hidden, "b", "", y, "autoZero"),
            flag("crossBetween", "midCat"),
            va = el("valAx"),
        )
    } else {
        format!(
            "<{ca}>{}{}{}{}</{ca}>",
            common(x, hidden, "b", "", y, "autoZero"),
            flag("auto", "1"),
            flag("lblAlgn", "ctr"),
            flag("lblOffset", "100"),
            ca = el("catAx"),
        )
    };
    let gridlines = if secondary {
        String::new()
    } else {
        format!("<{}/>", el("majorGridlines"))
    };
    let between = if value { "midCat" } else { "between" };
    format!(
        "{x_axis}<{va}>{}{}</{va}>",
        common(y, "0", side, &gridlines, x, crosses),
        flag("crossBetween", between),
        va = el("valAx"),
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
