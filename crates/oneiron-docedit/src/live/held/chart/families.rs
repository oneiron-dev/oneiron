//! A chart part's family settings as the live model holds them (OF-510, FIX
//! 3493 D9b): each plot's settings, the nth plot of its family by itself
//! ([`ChartPlot`]), the chart's 3D view ([`ChartView`]), and the on/off
//! settings of a plot or series. A value the reader does not read is no
//! setting: its bytes stay as they are.

use super::C;
use crate::edit::xml;
use crate::live::pptx::{
    BarDirection, BarShape, ChartKind, ChartPlot, ChartView, PlotGrouping, SizeRepresents,
};
use crate::ooxml::XmlTree;
use std::str::FromStr;

/// The `val` of `at`'s child `name`.
fn val<'t>(tree: &'t XmlTree, at: usize, name: &str) -> Option<&'t str> {
    tree.nodes[xml::child(tree, at, C, name)?].attr("val")
}

/// `at`'s child `name` as a number (a percentage's sign dropped).
fn number<T: FromStr>(tree: &XmlTree, at: usize, name: &str) -> Option<T> {
    val(tree, at, name)?
        .trim()
        .trim_end_matches('%')
        .parse()
        .ok()
}

/// `at`'s child `name` as an on/off setting: on when it holds no value.
pub(crate) fn flag(tree: &XmlTree, at: usize, name: &str) -> Option<bool> {
    let node = xml::child(tree, at, C, name)?;
    match tree.nodes[node].attr("val").map(str::trim) {
        None | Some("1" | "true") => Some(true),
        Some("0" | "false") => Some(false),
        Some(_) => None,
    }
}

/// One plot's settings as its plot element holds them, the `nth` plot of
/// `kind`: only those `kind` holds.
pub(crate) fn plot(tree: &XmlTree, kind: ChartKind, nth: u32, at: usize) -> ChartPlot {
    let mut read = ChartPlot {
        bar_dir: val(tree, at, "barDir").and_then(BarDirection::parse),
        grouping: val(tree, at, "grouping").and_then(PlotGrouping::parse),
        shape: val(tree, at, "shape").and_then(BarShape::parse),
        gap_depth: number(tree, at, "gapDepth"),
        bubble_3d: flag(tree, at, "bubble3D"),
        bubble_scale: number(tree, at, "bubbleScale"),
        show_neg_bubbles: flag(tree, at, "showNegBubbles"),
        size_represents: val(tree, at, "sizeRepresents").and_then(SizeRepresents::parse),
        ..ChartPlot::new(kind, nth)
    };
    super::special::read(tree, kind, at, &mut read);
    read.fit(kind, nth).0
}

/// The settings of each plot of `plots` that holds any, each the nth plot
/// of its family in document order.
pub(super) fn plots(tree: &XmlTree, plots: &[(ChartKind, usize)]) -> Vec<ChartPlot> {
    plots
        .iter()
        .enumerate()
        .map(|(index, &(kind, at))| {
            let nth = plots[..index]
                .iter()
                .filter(|(other, _)| *other == kind)
                .count();
            plot(tree, kind, u32::try_from(nth).unwrap_or(u32::MAX), at)
        })
        .filter(|read| !read.is_empty())
        .collect()
}

/// The chart's `c:view3D`, as the live model holds it.
pub(crate) fn view(tree: &XmlTree) -> Option<ChartView> {
    let at = xml::path(tree, 0, &[(C, "chart"), (C, "view3D")])?;
    Some(ChartView {
        rot_x: number(tree, at, "rotX"),
        h_percent: number(tree, at, "hPercent"),
        rot_y: number(tree, at, "rotY"),
        depth_percent: number(tree, at, "depthPercent"),
        r_ang_ax: flag(tree, at, "rAngAx"),
        perspective: number(tree, at, "perspective"),
    })
}
