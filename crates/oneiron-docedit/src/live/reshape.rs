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

mod chart;
mod dataset;
mod layout;
mod points;
mod series;
mod table;
mod workbook;

pub(super) use chart::{chart, reseed};
pub(super) use layout::plot_plan;
pub(super) use table::table;

use super::LiveError;
use super::held::{self, C};
use super::pptx::{ChartKind, NodePayload, draws_categories, effective_categories};
use crate::design_plan::Cell;
use crate::edit::xml::{self, P, R};
use crate::native_patch::{Target, chart_data, number};
use crate::ooxml::{Node, XmlTree, escape_text};
use crate::retained_opc::Package;
use layout::number_cells;
use points::{Points, carried, remap};

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

/// A kept series with its sequences replaced: `idx` and `order` as held,
/// `tx` (inserted after `order` when it had none), the category (or x)
/// slot before the value slot, and its data points' formatting and labels
/// carried to their points' new places ([`Points`]), those of points gone
/// dropped. Everything else keeps its bytes.
fn kept_ser(
    bytes: &[u8],
    tree: &XmlTree,
    ser: usize,
    (idx, order): (u32, u32),
    writer: &Writer,
    [tx, cat, val]: [&str; 3],
    points: &Points,
) -> Result<Vec<u8>, LiveError> {
    let mut out = xml::open_tag(bytes, &tree.nodes[ser]);
    let (mut named, mut cat_done, mut data_done) = (false, false, false);
    let mut points_done = false;
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
                if !points_done {
                    out.extend(carried(
                        bytes,
                        tree,
                        &tree.nodes[ser].children,
                        "dPt",
                        points,
                    ));
                    points_done = true;
                }
            }
            "dLbls" if !node.empty => {
                out.extend(xml::open_tag(bytes, node));
                let mut labels_done = false;
                for &label in &node.children {
                    if !tree.nodes[label].is(C, "dLbl") {
                        out.extend_from_slice(piece(bytes, tree, label));
                    } else if !labels_done {
                        out.extend(carried(bytes, tree, &node.children, "dLbl", points));
                        labels_done = true;
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
        } else if draws_categories(*want_family, now) {
            let (was_set, set) = (
                effective_categories(held_categories, was),
                effective_categories(categories, now),
            );
            if was_set.depth() != set.depth() || !was_set.same_labels(set) {
                // A hierarchy is written by the full rewrite.
                if set.depth() > 1 || was_set.depth() > 1 {
                    return None;
                }
                let held = line.categories.as_ref()?;
                if held.cache.len() != set.len() {
                    return None;
                }
                // A number category stays a number.
                let cells = set
                    .labels()
                    .into_iter()
                    .zip(&held.cache)
                    .map(|(category, cell)| match cell {
                        Cell::Number(_) => category
                            .parse()
                            .map_or_else(|_| Cell::Text(category.clone()), Cell::Number),
                        _ => Cell::Text(category),
                    })
                    .collect();
                writes.push((index, Target::Categories, cells));
            }
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

/// `read` reads as `wanted`: the same family and series names, each series
/// in the same plot family drawing the same categories (by label, level by
/// level, whatever their identities and whichever set holds them), and the
/// same values and x values (as numbers; a sequence ending in missing
/// points reads as one without them).
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
        let number = |value: Option<&Option<serde_json::Number>>| {
            value.and_then(|value| value.as_ref()?.as_f64())
        };
        (0..read.len().max(wanted.len())).all(|at| number(read.get(at)) == number(wanted.get(at)))
    };
    family == want_family
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
                && (!draws_categories(*family, a) || {
                    let (read, want) = (
                        effective_categories(categories, a),
                        effective_categories(want_categories, b),
                    );
                    read.depth() == want.depth() && read.same_labels(want)
                })
        })
}
