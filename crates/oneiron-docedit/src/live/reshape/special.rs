//! A rewritten chart's stock, surface and of-pie plots (OF-510, FIX 3493
//! D9c): the compound settings a plot element holds besides its scalar
//! ones, written where the model sets them and they differ from the held
//! bytes: high-low lines and up/down bars (their gap and fills), surface
//! band fills, of-pie series lines and the custom split, its points by
//! category identity at their new places. A data-only rewrite keeps every
//! one of them as it stands. A plot converted from another family carries
//! the ones its new family holds; a new plot takes its family's (CALLS, D9c
//! stock, surface and of-pie defaults). A stock series is drawn with no
//! line between its points, its close as a dot.
//! A stock price no series draws holds a placeholder series (FIX 9374).
//! Entry: `kept`, `fresh`, `same`, `defaults`, `overlay`, `stock_style`,
//! `stock_series`, `placeholder`.

use super::families::{applied, order, written};
use super::*;
use crate::edit::xml::A;
use crate::live::pptx::{
    ChartPlot, NodeId, OfPieType, SplitType, StockOrder, SurfaceBand, lines_and_bars, surface,
};

/// The compound plot children a plot converted from another family
/// carries when its new family holds them.
const CARRIED: &[&str] = &["hiLowLines", "upDownBars", "bandFmts", "serLines"];
/// The fills a `c:spPr` can hold.
const FILLS: &[&str] = &[
    "noFill",
    "solidFill",
    "gradFill",
    "blipFill",
    "pattFill",
    "grpFill",
];
/// An up/down bars element's children in schema order.
const BARS: &[&str] = &["gapWidth", "upBars", "downBars", "extLst"];
/// A band's or an up or down bar's children in schema order.
const STYLED: &[&str] = &["idx", "spPr", "extLst"];

/// The part a plot rewrite reads: its bytes and tree, the held plot a plot
/// converted from another family stood in, and the category identities the
/// plot's first series draws, in their new order.
pub(super) struct Context<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) tree: &'a XmlTree,
    pub(super) from: Option<usize>,
    pub(super) points: &'a [Option<NodeId>],
}

/// The DrawingML prefix the part's root binds (`a:` declared on the
/// element written when it binds none), and that declaration.
fn drawing(tree: &XmlTree) -> (String, String) {
    let bound = tree.nodes.first().and_then(|root| {
        root.attrs
            .iter()
            .find_map(|(name, value)| name.strip_prefix("xmlns:").filter(|_| value == A))
    });
    match bound {
        Some(prefix) => (format!("{prefix}:"), String::new()),
        None => ("a:".to_owned(), format!(r#" xmlns:a="{A}""#)),
    }
}

/// A solid fill of `rgb` (six hex digits, as the model checks them).
fn solid(tree: &XmlTree, rgb: &str) -> String {
    let (a, declared) = drawing(tree);
    format!(
        r#"<{a}solidFill{declared}><{a}srgbClr val="{}"/></{a}solidFill>"#,
        rgb.to_ascii_uppercase()
    )
}

/// The element at `at` (an up or down bar, a band) with its fill `rgb`:
/// the fill its `c:spPr` holds replaced (put after its geometry where it
/// holds none), the rest of it kept; a new `c:spPr` where it holds none.
fn filled(
    bytes: &[u8],
    tree: &XmlTree,
    at: usize,
    rgb: &str,
    writer: &Writer,
) -> Result<Vec<u8>, LiveError> {
    let fill = solid(tree, rgb);
    let Some(sp) = xml::child(tree, at, C, "spPr") else {
        let sp = format!("<{s}>{fill}</{s}>", s = writer.el("spPr"));
        let splices = written(bytes, tree, at, STYLED, &[("spPr", sp.into_bytes())], |n| n);
        return applied(bytes, tree, at, splices);
    };
    let node = &tree.nodes[sp];
    let find = |names: &[&str], last: bool| -> Option<usize> {
        let mut found = node.children.iter().copied().filter(|&child| {
            tree.nodes[child].namespace == A && names.contains(&tree.nodes[child].name.as_str())
        });
        if last { found.last() } else { found.next() }
    };
    let splice = match find(FILLS, false) {
        Some(old) => (tree.nodes[old].span.clone(), fill.into_bytes()),
        None => match find(&["xfrm", "custGeom", "prstGeom"], true) {
            Some(shape) => {
                let end = tree.nodes[shape].span.end;
                (end..end, fill.into_bytes())
            }
            None => xml::insert_first(bytes, node, &fill),
        },
    };
    applied(bytes, tree, at, vec![splice])
}

/// An element `name` with no value: one a plot draws by holding it.
fn mark(writer: &Writer, name: &str) -> Vec<u8> {
    format!("<{}/>", writer.el(name)).into_bytes()
}

/// New up/down bars: their gap (150 percent where the model sets none) and
/// each bar's fill the model sets.
fn bars(tree: &XmlTree, writer: &Writer, plot: &ChartPlot) -> Vec<u8> {
    let bar = |name: &str, fill: Option<&String>| match fill {
        Some(rgb) => format!(
            "<{b}><{s}>{}</{s}></{b}>",
            solid(tree, rgb),
            b = writer.el(name),
            s = writer.el("spPr")
        ),
        None => format!("<{}/>", writer.el(name)),
    };
    format!(
        r#"<{u}><{g} val="{}"/>{}{}</{u}>"#,
        plot.up_down_gap_width.unwrap_or(150),
        bar("upBars", plot.up_fill.as_ref()),
        bar("downBars", plot.down_fill.as_ref()),
        u = writer.el("upDownBars"),
        g = writer.el("gapWidth"),
    )
    .into_bytes()
}

/// A custom split over the point indices `points` names.
fn split_xml(writer: &Writer, points: &[usize]) -> Vec<u8> {
    let pts: String = points
        .iter()
        .map(|at| format!(r#"<{} val="{at}"/>"#, writer.el("secondPiePt")))
        .collect();
    format!("<{c}>{pts}</{c}>", c = writer.el("custSplit")).into_bytes()
}

/// The indices of the points `split` names, in the set `points`, ascending.
fn indices(split: &[NodeId], points: &[Option<NodeId>]) -> Vec<usize> {
    let mut out: Vec<usize> = split
        .iter()
        .filter_map(|id| points.iter().position(|point| *point == Some(*id)))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The bands' fills `wanted` sets written over the `c:bandFmts` at `kept`
/// (each band's own bytes otherwise kept, a band it lacks added), or a new
/// one; `None` when nothing differs.
fn banded(
    ctx: &Context<'_>,
    kept: Option<usize>,
    wanted: &[SurfaceBand],
    writer: &Writer,
) -> Result<Option<Vec<u8>>, LiveError> {
    let (bytes, tree) = (ctx.bytes, ctx.tree);
    let have = |index: u32| {
        kept.into_iter()
            .flat_map(|bands| held::children(tree, bands, C, "bandFmt"))
            .find(|&band| int(tree, band, "idx") == Some(index))
    };
    let mut splices = Vec::new();
    let mut added = String::new();
    for band in wanted {
        let Some(rgb) = &band.fill else {
            continue;
        };
        match have(band.index) {
            Some(at) if held::fill(tree, at).is_some_and(|fill| fill.eq_ignore_ascii_case(rgb)) => {
            }
            Some(at) => splices.push((
                tree.nodes[at].span.clone(),
                filled(bytes, tree, at, rgb, writer)?,
            )),
            None => added.push_str(&format!(
                r#"<{b}><{i} val="{}"/><{s}>{}</{s}></{b}>"#,
                band.index,
                solid(tree, rgb),
                b = writer.el("bandFmt"),
                i = writer.el("idx"),
                s = writer.el("spPr"),
            )),
        }
    }
    if splices.is_empty() && added.is_empty() {
        return Ok(None);
    }
    Ok(Some(match kept {
        Some(at) => {
            if !added.is_empty() {
                splices.push(xml::insert_end(bytes, &tree.nodes[at], added.as_bytes()));
            }
            applied(bytes, tree, at, splices)?
        }
        None => format!("<{b}>{added}</{b}>", b = writer.el("bandFmts")).into_bytes(),
    }))
}

/// The compound settings `wanted` sets for the `kind` plot at `at` (held
/// bytes), each written where it differs from what the plot holds: an
/// element added or dropped, up/down bars' gap and fills and bands' fills
/// written over their own bytes, a custom split's points at their new
/// places (`ctx.points`). Nothing for what `wanted` leaves unset.
pub(super) fn kept(
    ctx: &Context<'_>,
    at: usize,
    kind: ChartKind,
    wanted: Option<&ChartPlot>,
    writer: &Writer,
) -> Result<Vec<(&'static str, Vec<u8>)>, LiveError> {
    let (bytes, tree) = (ctx.bytes, ctx.tree);
    let Some(want) = wanted else {
        return Ok(Vec::new());
    };
    let child = |name: &str| xml::child(tree, at, C, name);
    let mut out: Vec<(&'static str, Vec<u8>)> = Vec::new();
    let presence = |out: &mut Vec<(&'static str, Vec<u8>)>,
                    name: &'static str,
                    on: Option<bool>| {
        match (on, child(name).is_some()) {
            (Some(true), false) => out.push((name, mark(writer, name))),
            (Some(false), true) => out.push((name, Vec::new())),
            _ => {}
        }
    };
    if lines_and_bars(kind) {
        presence(&mut out, "hiLowLines", want.hi_low_lines);
        match (want.up_down_bars, child("upDownBars")) {
            (Some(false), Some(_)) => out.push(("upDownBars", Vec::new())),
            (Some(true), None) => out.push(("upDownBars", bars(tree, writer, want))),
            (_, Some(old)) => {
                let mut entries: Vec<(&str, Vec<u8>)> = Vec::new();
                if let Some(gap) = want.up_down_gap_width
                    && int(tree, old, "gapWidth") != Some(gap)
                {
                    entries.push((
                        "gapWidth",
                        format!(r#"<{} val="{gap}"/>"#, writer.el("gapWidth")).into_bytes(),
                    ));
                }
                for (name, fill) in [("upBars", &want.up_fill), ("downBars", &want.down_fill)] {
                    let Some(rgb) = fill else {
                        continue;
                    };
                    let bar = xml::child(tree, old, C, name);
                    if bar
                        .and_then(|bar| held::fill(tree, bar))
                        .is_some_and(|have| have.eq_ignore_ascii_case(rgb))
                    {
                        continue;
                    }
                    entries.push((
                        name,
                        match bar {
                            Some(bar) => filled(bytes, tree, bar, rgb, writer)?,
                            None => format!(
                                "<{b}><{s}>{}</{s}></{b}>",
                                solid(tree, rgb),
                                b = writer.el(name),
                                s = writer.el("spPr")
                            )
                            .into_bytes(),
                        },
                    ));
                }
                if !entries.is_empty() {
                    let splices = written(bytes, tree, old, BARS, &entries, |n| n);
                    out.push(("upDownBars", applied(bytes, tree, old, splices)?));
                }
            }
            _ => {}
        }
    }
    if surface(kind)
        && let Some(bands) = &want.bands
        && let Some(xml) = banded(ctx, child("bandFmts"), bands, writer)?
    {
        out.push(("bandFmts", xml));
    }
    if kind == ChartKind::OfPie {
        presence(&mut out, "serLines", want.ser_lines);
        if let Some(split) = &want.custom_split {
            let now = indices(split, ctx.points);
            let mut was = held::split(tree, at);
            was.sort_unstable();
            was.dedup();
            match child("custSplit") {
                Some(_) if now.is_empty() => out.push(("custSplit", Vec::new())),
                Some(_) if now == was => {}
                None if now.is_empty() => {}
                _ => out.push(("custSplit", split_xml(writer, &now))),
            }
        }
    }
    Ok(out)
}

/// The compound children a plot written fresh in `kind` holds: those its
/// held plot (`ctx.from`, of another family) holds and `kind` does too,
/// with the model's settings (`settings`, over the family's defaults)
/// written over them; else as `settings` sets them: high-low lines in a
/// stock plot, up/down bars in an OHLC one, the series lines of an of-pie
/// plot.
pub(super) fn fresh(
    ctx: &Context<'_>,
    kind: ChartKind,
    settings: &ChartPlot,
    writer: &Writer,
) -> Result<Vec<(&'static str, Vec<u8>)>, LiveError> {
    let holds = order(kind);
    let mut out: Vec<(&'static str, Vec<u8>)> = Vec::new();
    if let Some(from) = ctx.from {
        for &name in CARRIED.iter().filter(|name| holds.contains(*name)) {
            if let Some(at) = xml::child(ctx.tree, from, C, name) {
                out.push((name, piece(ctx.bytes, ctx.tree, at).to_vec()));
            }
        }
        for (name, bytes) in kept(ctx, from, kind, Some(settings), writer)? {
            out.retain(|(held, _)| *held != name);
            out.push((name, bytes));
        }
    }
    let has = |out: &[(&str, Vec<u8>)], name: &str| out.iter().any(|(held, _)| *held == name);
    if lines_and_bars(kind) {
        let ohlc = settings
            .stock
            .is_some_and(|roles| roles.order == StockOrder::Ohlc);
        if settings.hi_low_lines.unwrap_or(false) && !has(&out, "hiLowLines") {
            out.push(("hiLowLines", mark(writer, "hiLowLines")));
        }
        let up_down = settings
            .up_down_bars
            .unwrap_or(kind == ChartKind::Stock && ohlc);
        if up_down && !has(&out, "upDownBars") {
            out.push(("upDownBars", bars(ctx.tree, writer, settings)));
        }
    }
    if surface(kind)
        && !has(&out, "bandFmts")
        && let Some(bands) = &settings.bands
        && let Some(xml) = banded(ctx, None, bands, writer)?
    {
        out.push(("bandFmts", xml));
    }
    if kind == ChartKind::OfPie {
        if settings.ser_lines.unwrap_or(false) && !has(&out, "serLines") {
            out.push(("serLines", mark(writer, "serLines")));
        }
        let now = settings
            .custom_split
            .as_ref()
            .map_or_else(Vec::new, |split| indices(split, ctx.points));
        if !now.is_empty() {
            out.retain(|(held, _)| *held != "custSplit");
            out.push(("custSplit", split_xml(writer, &now)));
        }
    }
    out.retain(|(_, bytes)| !bytes.is_empty());
    Ok(out)
}

/// The settings a new stock, surface or of-pie plot takes where the model
/// sets none (CALLS, D9c defaults): a stock plot draws high-low lines (and
/// up/down bars when it is OHLC, [`fresh`]); a surface is filled, not a
/// wireframe; an of-pie plot's second plot is a pie 75 percent of the
/// first, 100 percent apart, its points split as the application picks,
/// joined by series lines.
pub(super) fn defaults(kind: ChartKind, plot: &mut ChartPlot) {
    match kind {
        ChartKind::Stock => plot.hi_low_lines = Some(true),
        ChartKind::Surface | ChartKind::Surface3D => plot.wireframe = Some(false),
        ChartKind::OfPie => {
            plot.of_pie_type = Some(OfPieType::Pie);
            plot.split_type = Some(SplitType::Auto);
            plot.gap_width = Some(100);
            plot.second_pie_size = Some(75);
            plot.ser_lines = Some(true);
        }
        _ => {}
    }
}

/// `settings` with each special setting `plot` sets over it.
pub(super) fn overlay(plot: &ChartPlot, settings: &mut ChartPlot) {
    settings.stock = plot.stock.or(settings.stock);
    settings.hi_low_lines = plot.hi_low_lines.or(settings.hi_low_lines);
    settings.up_down_bars = plot.up_down_bars.or(settings.up_down_bars);
    settings.up_down_gap_width = plot.up_down_gap_width.or(settings.up_down_gap_width);
    settings.up_fill = plot.up_fill.clone().or(settings.up_fill.take());
    settings.down_fill = plot.down_fill.clone().or(settings.down_fill.take());
    settings.wireframe = plot.wireframe.or(settings.wireframe);
    settings.bands = plot.bands.clone().or(settings.bands.take());
    settings.of_pie_type = plot.of_pie_type.or(settings.of_pie_type);
    settings.split_type = plot.split_type.or(settings.split_type);
    settings.split_pos = plot.split_pos.clone().or(settings.split_pos.take());
    settings.custom_split = plot.custom_split.clone().or(settings.custom_split.take());
    settings.second_pie_size = plot.second_pie_size.or(settings.second_pie_size);
    settings.gap_width = plot.gap_width.or(settings.gap_width);
    settings.ser_lines = plot.ser_lines.or(settings.ser_lines);
}

/// Whether the plot a part holds (`have`, read without identities) holds
/// every compound setting `want` sets: an element drawn or not, up/down
/// bars' gap and fills, and band fills. Stock prices and custom splits are
/// compared by identity ([`held::same_named`]).
pub(super) fn same(have: Option<&ChartPlot>, want: &ChartPlot) -> bool {
    let on = |value: Option<bool>, have: Option<bool>| {
        value.is_none_or(|on| have.unwrap_or(false) == on)
    };
    let color = |value: &Option<String>, have: Option<&String>| {
        value
            .as_ref()
            .is_none_or(|rgb| have.is_some_and(|have| have.eq_ignore_ascii_case(rgb)))
    };
    let held = |field: fn(&ChartPlot) -> Option<bool>| have.and_then(field);
    on(want.hi_low_lines, held(|plot| plot.hi_low_lines))
        && on(want.up_down_bars, held(|plot| plot.up_down_bars))
        && on(want.ser_lines, held(|plot| plot.ser_lines))
        && want
            .up_down_gap_width
            .is_none_or(|gap| have.and_then(|plot| plot.up_down_gap_width) == Some(gap))
        && color(&want.up_fill, have.and_then(|plot| plot.up_fill.as_ref()))
        && color(
            &want.down_fill,
            have.and_then(|plot| plot.down_fill.as_ref()),
        )
        && want.bands.iter().flatten().all(|band| {
            let held = have
                .and_then(|plot| plot.bands.as_ref())
                .and_then(|bands| bands.iter().find(|held| held.index == band.index));
            color(&band.fill, held.and_then(|held| held.fill.as_ref()))
        })
}

/// A stock series' line and marker: no line between its points, and no
/// marker but on its close, a dot.
pub(super) fn stock_style(tree: &XmlTree, writer: &Writer, close: bool) -> (Vec<u8>, Vec<u8>) {
    let (a, declared) = drawing(tree);
    let line = format!(
        r#"<{s}><{a}ln w="19050"{declared}><{a}noFill/></{a}ln></{s}>"#,
        s = writer.el("spPr")
    );
    let symbol = |name: &str, value: &str| format!(r#"<{} val="{value}"/>"#, writer.el(name));
    let marker = format!(
        "<{m}>{}{}</{m}>",
        symbol("symbol", if close { "dot" } else { "none" }),
        if close {
            symbol("size", "5")
        } else {
            String::new()
        },
        m = writer.el("marker")
    );
    (line.into_bytes(), marker.into_bytes())
}

/// A series written new in a stock plot: its `idx` and `order`, name,
/// [`stock_style`], categories and values.
pub(super) fn stock_series(
    tree: &XmlTree,
    writer: &Writer,
    (idx, order): (u32, u32),
    close: bool,
    [tx, cat, val]: [&str; 3],
) -> Vec<u8> {
    let (line, marker) = stock_style(tree, writer, close);
    let mut out = format!(
        r#"<{ser}><{i} val="{idx}"/><{o} val="{order}"/>{tx}"#,
        ser = writer.el("ser"),
        i = writer.el("idx"),
        o = writer.el("order"),
    )
    .into_bytes();
    out.extend(line);
    out.extend(marker);
    out.extend(
        format!(
            r#"{cat}{val}<{s} val="0"/></{ser}>"#,
            s = writer.el("smooth"),
            ser = writer.el("ser")
        )
        .into_bytes(),
    );
    out
}

/// A stock plot's placeholder for a price no series draws (FIX 9374): its
/// `idx` and `order`, an empty name, [`stock_style`] and no categories or
/// values, so the plot keeps its three or four series, each price its
/// place, and nothing is drawn for it. Every reader skips it
/// ([`crate::native_patch::stock_placeholder`]).
pub(super) fn placeholder(tree: &XmlTree, writer: &Writer, (idx, order): (u32, u32)) -> Vec<u8> {
    let (line, marker) = stock_style(tree, writer, false);
    let mut out = format!(
        r#"<{ser}><{i} val="{idx}"/><{o} val="{order}"/><{t}><{v}></{v}></{t}>"#,
        ser = writer.el("ser"),
        i = writer.el("idx"),
        o = writer.el("order"),
        t = writer.el("tx"),
        v = writer.el("v"),
    )
    .into_bytes();
    out.extend(line);
    out.extend(marker);
    out.extend(
        format!(
            r#"<{s} val="0"/></{ser}>"#,
            s = writer.el("smooth"),
            ser = writer.el("ser")
        )
        .into_bytes(),
    );
    out
}
