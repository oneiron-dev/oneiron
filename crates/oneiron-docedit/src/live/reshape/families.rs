//! A rewritten chart's plots and 3D view (OF-510, FIX 3493 D9b): a kept
//! plot with its series replaced and only the settings the model changed
//! written over its bytes, a plot written fresh in its family (its settings
//! the model's, else the family's defaults), and the chart's `c:view3D`
//! written where the model's view differs from the one it holds. Each plot
//! takes the settings of the nth plot of its family ([`ChartPlot`]).
//! Entry: `kept_plot`, `fresh_plot`, `view`, `same_settings`.

use super::*;
use crate::edit::xml::Splice;
use crate::live::pptx::{BarDirection, BarShape, ChartPlot, ChartView, PlotGrouping};

/// A `c:view3D`'s children in schema order.
const VIEW_ORDER: &[&str] = &[
    "rotX",
    "hPercent",
    "rotY",
    "depthPercent",
    "rAngAx",
    "perspective",
    "extLst",
];

/// A plot element's children in schema order, its series as `ser`.
fn order(kind: ChartKind) -> &'static [&'static str] {
    match kind {
        ChartKind::Bar => &[
            "barDir",
            "grouping",
            "varyColors",
            "ser",
            "dLbls",
            "gapWidth",
            "overlap",
            "serLines",
            "axId",
            "extLst",
        ],
        ChartKind::Bar3D => &[
            "barDir",
            "grouping",
            "varyColors",
            "ser",
            "dLbls",
            "gapWidth",
            "gapDepth",
            "shape",
            "axId",
            "extLst",
        ],
        ChartKind::Line => &[
            "grouping",
            "varyColors",
            "ser",
            "dLbls",
            "dropLines",
            "hiLowLines",
            "upDownBars",
            "marker",
            "smooth",
            "axId",
            "extLst",
        ],
        ChartKind::Line3D => &[
            "grouping",
            "varyColors",
            "ser",
            "dLbls",
            "dropLines",
            "gapDepth",
            "axId",
            "extLst",
        ],
        ChartKind::Area => &[
            "grouping",
            "varyColors",
            "ser",
            "dLbls",
            "dropLines",
            "axId",
            "extLst",
        ],
        ChartKind::Area3D => &[
            "grouping",
            "varyColors",
            "ser",
            "dLbls",
            "dropLines",
            "gapDepth",
            "axId",
            "extLst",
        ],
        ChartKind::Pie => &["varyColors", "ser", "dLbls", "firstSliceAng", "extLst"],
        ChartKind::Pie3D => &["varyColors", "ser", "dLbls", "extLst"],
        ChartKind::Doughnut => &[
            "varyColors",
            "ser",
            "dLbls",
            "firstSliceAng",
            "holeSize",
            "extLst",
        ],
        ChartKind::Radar => &["radarStyle", "varyColors", "ser", "dLbls", "axId", "extLst"],
        ChartKind::Scatter => &[
            "scatterStyle",
            "varyColors",
            "ser",
            "dLbls",
            "axId",
            "extLst",
        ],
        ChartKind::Bubble => &[
            "varyColors",
            "ser",
            "dLbls",
            "bubble3D",
            "bubbleScale",
            "showNegBubbles",
            "sizeRepresents",
            "axId",
            "extLst",
        ],
    }
}

/// The settings a new plot of `kind` takes where the model sets none: bars
/// as clustered columns (box-shaped in 3D), lines and areas standing one
/// behind another, bubbles at their full scale without negative ones (CALLS,
/// D9b fresh plot settings).
fn defaults(kind: ChartKind) -> ChartPlot {
    let mut plot = ChartPlot::new(kind, 0);
    match kind {
        ChartKind::Bar | ChartKind::Bar3D => {
            plot.bar_dir = Some(BarDirection::Col);
            plot.grouping = Some(PlotGrouping::Clustered);
            if kind == ChartKind::Bar3D {
                plot.shape = Some(BarShape::Box);
            }
        }
        ChartKind::Line | ChartKind::Line3D | ChartKind::Area | ChartKind::Area3D => {
            plot.grouping = Some(PlotGrouping::Standard);
        }
        ChartKind::Bubble => {
            plot.bubble_scale = Some(100);
            plot.show_neg_bubbles = Some(false);
        }
        _ => {}
    }
    plot
}

/// One on/off value as a chart part writes it.
pub(super) fn bit(on: bool) -> &'static str {
    if on { "1" } else { "0" }
}

/// A plot's settings as its elements' names and values.
fn tokens(plot: &ChartPlot) -> Vec<(&'static str, String)> {
    [
        ("barDir", plot.bar_dir.map(|value| value.token().to_owned())),
        (
            "grouping",
            plot.grouping.map(|value| value.token().to_owned()),
        ),
        ("shape", plot.shape.map(|value| value.token().to_owned())),
        ("gapDepth", plot.gap_depth.map(|value| value.to_string())),
        ("bubble3D", plot.bubble_3d.map(|on| bit(on).to_owned())),
        (
            "bubbleScale",
            plot.bubble_scale.map(|value| value.to_string()),
        ),
        (
            "showNegBubbles",
            plot.show_neg_bubbles.map(|on| bit(on).to_owned()),
        ),
        (
            "sizeRepresents",
            plot.size_represents.map(|value| value.token().to_owned()),
        ),
    ]
    .into_iter()
    .filter_map(|(name, value)| Some((name, value?)))
    .collect()
}

fn flag(writer: &Writer, name: &str, value: &str) -> Vec<u8> {
    format!(r#"<{} val="{value}"/>"#, writer.el(name)).into_bytes()
}

fn ids_xml(writer: &Writer, ids: &[u32]) -> Vec<u8> {
    ids.iter()
        .flat_map(|id| flag(writer, "axId", &id.to_string()))
        .collect()
}

/// The splices that write `entries` among `node`'s children, each by its
/// element name (its `c:` namespace): the first child of that name takes
/// the entry's bytes and any later one goes, and an entry the node does not
/// hold goes before the first child `order` puts after it, else at the
/// end. Every other child, and the bytes between children, keep theirs.
/// `alias` names a child as the entry it stands for.
pub(super) fn written(
    bytes: &[u8],
    tree: &XmlTree,
    node: usize,
    order: &[&str],
    entries: &[(&str, Vec<u8>)],
    alias: impl Fn(&str) -> &str,
) -> Vec<Splice> {
    let rank = |name: &str| order.iter().position(|at| *at == name);
    let mut done = vec![false; entries.len()];
    let mut out: Vec<Splice> = Vec::new();
    let mut pending: Vec<u8> = Vec::new();
    for &child in &tree.nodes[node].children {
        let element = &tree.nodes[child];
        if element.namespace != C {
            continue;
        }
        let name = alias(&element.name);
        if let Some(here) = rank(name) {
            for (at, (entry, bytes)) in entries.iter().enumerate() {
                if !done[at] && rank(*entry).is_some_and(|rank| rank < here) {
                    done[at] = true;
                    pending.extend_from_slice(bytes);
                }
            }
            if !pending.is_empty() {
                let start = element.span.start;
                out.push((start..start, std::mem::take(&mut pending)));
            }
        }
        if let Some(at) = entries.iter().position(|(entry, _)| *entry == name) {
            let bytes = if done[at] {
                Vec::new()
            } else {
                done[at] = true;
                entries[at].1.clone()
            };
            out.push((element.span.clone(), bytes));
        }
    }
    for (at, (_, bytes)) in entries.iter().enumerate() {
        if !done[at] {
            pending.extend_from_slice(bytes);
        }
    }
    if !pending.is_empty() {
        out.push(xml::insert_end(bytes, &tree.nodes[node], &pending));
    }
    out
}

/// `node`'s bytes with `splices` (on the whole part's bytes) applied.
pub(super) fn applied(
    bytes: &[u8],
    tree: &XmlTree,
    node: usize,
    splices: Vec<Splice>,
) -> Result<Vec<u8>, LiveError> {
    let span = tree.nodes[node].span.clone();
    let local = splices
        .into_iter()
        .map(|(range, value)| {
            (
                range.start.saturating_sub(span.start)..range.end.saturating_sub(span.start),
                value,
            )
        })
        .collect();
    Ok(xml::splice(&bytes[span], local)?)
}

/// The settings the `nth` plot of `kind` is written with: the model's
/// (`plots`), those `kind` does not hold left out.
fn wanted(plots: &[ChartPlot], kind: ChartKind, nth: u32) -> Option<ChartPlot> {
    plots
        .iter()
        .find(|plot| plot.is(kind, nth))
        .map(|plot| plot.fit(kind, nth).0)
}

/// How a target plot lays its series out, for its axes: the model's
/// setting, else the kept plot's own, else its family's default.
pub(super) fn grouping(
    tree: &XmlTree,
    kept: Option<usize>,
    kind: ChartKind,
    plots: &[ChartPlot],
    nth: u32,
) -> Option<PlotGrouping> {
    wanted(plots, kind, nth)
        .and_then(|plot| plot.grouping)
        .or_else(|| kept.and_then(|at| held::plot_settings(tree, kind, nth, at).grouping))
        .or_else(|| defaults(kind).grouping)
}

/// A kept plot with its series replaced where they stood, each setting the
/// model sets (`plots`, the `nth` plot of `kind`) written where it differs
/// from the plot's own, and its axis ids replaced by `ids` when the plot's
/// axes changed. Everything else keeps its bytes.
#[allow(clippy::too_many_arguments)]
pub(super) fn kept_plot(
    bytes: &[u8],
    tree: &XmlTree,
    plot: usize,
    (kind, nth): (ChartKind, u32),
    sers: &[u8],
    plots: &[ChartPlot],
    ids: Option<&[u32]>,
    writer: &Writer,
) -> Result<Vec<u8>, LiveError> {
    let held = tokens(&held::plot_settings(tree, kind, nth, plot));
    let mut entries: Vec<(&str, Vec<u8>)> = vec![("ser", sers.to_vec())];
    if let Some(plot) = wanted(plots, kind, nth) {
        for (name, value) in tokens(&plot) {
            if !held.contains(&(name, value.clone())) {
                entries.push((name, flag(writer, name, &value)));
            }
        }
    }
    if let Some(ids) = ids {
        entries.push(("axId", ids_xml(writer, ids)));
    }
    let splices = written(bytes, tree, plot, order(kind), &entries, |name| name);
    applied(bytes, tree, plot, splices)
}

/// A plot written fresh in `kind`: that family's required elements, its
/// settings the model's (`plots`, the `nth` plot of `kind`) and else the
/// family's defaults, the series, and the axis ids it plots on.
pub(super) fn fresh_plot(
    (kind, nth): (ChartKind, u32),
    writer: &Writer,
    sers: &[u8],
    ids: &[u32],
    plots: &[ChartPlot],
) -> Vec<u8> {
    let mut settings = defaults(kind);
    if let Some(plot) = wanted(plots, kind, nth) {
        settings = ChartPlot {
            bar_dir: plot.bar_dir.or(settings.bar_dir),
            grouping: plot.grouping.or(settings.grouping),
            shape: plot.shape.or(settings.shape),
            gap_depth: plot.gap_depth.or(settings.gap_depth),
            bubble_3d: plot.bubble_3d.or(settings.bubble_3d),
            bubble_scale: plot.bubble_scale.or(settings.bubble_scale),
            show_neg_bubbles: plot.show_neg_bubbles.or(settings.show_neg_bubbles),
            size_represents: plot.size_represents.or(settings.size_represents),
            ..settings
        };
    }
    let pie = matches!(
        kind,
        ChartKind::Pie | ChartKind::Pie3D | ChartKind::Doughnut
    );
    let mut parts: Vec<(&str, Vec<u8>)> = tokens(&settings)
        .into_iter()
        .map(|(name, value)| (name, flag(writer, name, &value)))
        .collect();
    parts.push(("varyColors", flag(writer, "varyColors", bit(pie))));
    parts.push(("ser", sers.to_vec()));
    parts.push(("axId", ids_xml(writer, ids)));
    match kind {
        ChartKind::Bar | ChartKind::Bar3D => {
            parts.push(("gapWidth", flag(writer, "gapWidth", "150")));
        }
        ChartKind::Line => parts.push(("marker", flag(writer, "marker", "1"))),
        ChartKind::Radar => parts.push(("radarStyle", flag(writer, "radarStyle", "marker"))),
        ChartKind::Scatter => {
            parts.push(("scatterStyle", flag(writer, "scatterStyle", "lineMarker")));
        }
        ChartKind::Pie => parts.push(("firstSliceAng", flag(writer, "firstSliceAng", "0"))),
        ChartKind::Doughnut => {
            parts.push(("firstSliceAng", flag(writer, "firstSliceAng", "0")));
            parts.push(("holeSize", flag(writer, "holeSize", "50")));
        }
        _ => {}
    }
    let name = writer.el(kind.element());
    let mut out = format!("<{name}>").into_bytes();
    for element in order(kind) {
        for (part, bytes) in &parts {
            if part == element {
                out.extend_from_slice(bytes);
            }
        }
    }
    out.extend(format!("</{name}>").into_bytes());
    out
}

/// The splice that writes the model's 3D view (`wanted`) into the chart
/// part: each setting it sets that differs from the part's `c:view3D`
/// written over it, the rest of that element kept; a new `c:view3D`
/// before the chart's walls and plot area when it holds none. `None` when
/// nothing differs.
pub(super) fn view(
    bytes: &[u8],
    tree: &XmlTree,
    wanted: Option<&ChartView>,
    writer: &Writer,
) -> Result<Option<Splice>, LiveError> {
    let (Some(wanted), Some(chart)) = (wanted, xml::child(tree, 0, C, "chart")) else {
        return Ok(None);
    };
    let held = held::view(tree).unwrap_or_default();
    let entries: Vec<(&str, Vec<u8>)> = [
        (
            "rotX",
            wanted
                .rot_x
                .filter(|_| wanted.rot_x != held.rot_x)
                .map(|value| value.to_string()),
        ),
        (
            "hPercent",
            wanted
                .h_percent
                .filter(|_| wanted.h_percent != held.h_percent)
                .map(|value| value.to_string()),
        ),
        (
            "rotY",
            wanted
                .rot_y
                .filter(|_| wanted.rot_y != held.rot_y)
                .map(|value| value.to_string()),
        ),
        (
            "depthPercent",
            wanted
                .depth_percent
                .filter(|_| wanted.depth_percent != held.depth_percent)
                .map(|value| value.to_string()),
        ),
        (
            "rAngAx",
            wanted
                .r_ang_ax
                .filter(|_| wanted.r_ang_ax != held.r_ang_ax)
                .map(|on| bit(on).to_owned()),
        ),
        (
            "perspective",
            wanted
                .perspective
                .filter(|_| wanted.perspective != held.perspective)
                .map(|value| value.to_string()),
        ),
    ]
    .into_iter()
    .filter_map(|(name, value)| Some((name, flag(writer, name, &value?))))
    .collect();
    if entries.is_empty() {
        return Ok(None);
    }
    if let Some(at) = xml::child(tree, chart, C, "view3D") {
        let splices = written(bytes, tree, at, VIEW_ORDER, &entries, |name| name);
        let span = tree.nodes[at].span.clone();
        return Ok(Some((span, applied(bytes, tree, at, splices)?)));
    }
    let name = writer.el("view3D");
    let mut element = format!("<{name}>").into_bytes();
    for (_, bytes) in &entries {
        element.extend_from_slice(bytes);
    }
    element.extend(format!("</{name}>").into_bytes());
    let before = tree.nodes[chart].children.iter().copied().find(|&child| {
        let node = &tree.nodes[child];
        node.namespace == C
            && matches!(
                node.name.as_str(),
                "floor" | "sideWall" | "backWall" | "plotArea"
            )
    });
    Ok(Some(match before {
        Some(at) => {
            let start = tree.nodes[at].span.start;
            (start..start, element)
        }
        None => xml::insert_end(bytes, &tree.nodes[chart], &element),
    }))
}

/// Whether the chart part `read` reads holds every setting `wanted` sets:
/// each plot's (the nth plot of its family), its 3D view's, and each
/// series' 3D bubbles (the series in one order). A setting `wanted` leaves
/// unset is any the part holds.
pub(in crate::live) fn same_settings(read: &NodePayload, wanted: &NodePayload) -> bool {
    let (
        NodePayload::Chart {
            plots: held,
            view: held_view,
            series: held_series,
            ..
        },
        NodePayload::Chart {
            plots,
            view,
            series,
            ..
        },
    ) = (read, wanted)
    else {
        return false;
    };
    let plots_held = plots.iter().all(|plot| {
        let have = held
            .iter()
            .find(|have| have.is(plot.family, plot.nth))
            .map(tokens)
            .unwrap_or_default();
        tokens(&plot.fit(plot.family, plot.nth).0)
            .iter()
            .all(|token| have.contains(token))
    });
    let view_held = view.is_none_or(|view| {
        let have = held_view.unwrap_or_default();
        [
            view.rot_x.is_none_or(|value| have.rot_x == Some(value)),
            view.h_percent
                .is_none_or(|value| have.h_percent == Some(value)),
            view.rot_y.is_none_or(|value| have.rot_y == Some(value)),
            view.depth_percent
                .is_none_or(|value| have.depth_percent == Some(value)),
            view.r_ang_ax
                .is_none_or(|value| have.r_ang_ax == Some(value)),
            view.perspective
                .is_none_or(|value| have.perspective == Some(value)),
        ]
        .into_iter()
        .all(|held| held)
    });
    plots_held
        && view_held
        && held_series
            .iter()
            .zip(series)
            .all(|(have, line)| line.bubble_3d.is_none_or(|on| have.bubble_3d == Some(on)))
}
