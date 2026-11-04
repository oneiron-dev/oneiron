//! Data labels and point formatting retyped to a new family (OF-510, FIX
//! 9276, 9275): a data label position stays where the new plot places
//! labels so (its family and grouping, FIX 10297), and goes where it does
//! not; a point's marker, explosion, 3D bubble, picture or negative
//! inversion goes where the new family draws none. Each label keeps its
//! text and its other settings, each point its fill and line, and every
//! other byte stays. What goes is named, as its chart part names it, for
//! the receipt.
//! A converted plot drops the filtered series it keeps in another
//! family's form (FIX 10298).
//! Entry: `position`, `point`, `labels`, `extensions`.

use super::families::applied;
use super::retained::order;
use super::*;
use crate::edit::xml::Splice;
use crate::live::pptx::PlotGrouping;

/// The namespace a plot's filtered (hidden) series extensions live in.
const C15: &str = "http://schemas.microsoft.com/office/drawing/2012/chart";

/// The point children only some families draw.
const POINT_ONLY: &[&str] = &[
    "invertIfNegative",
    "marker",
    "bubble3D",
    "explosion",
    "pictureOptions",
];

/// The data label positions a `kind` plot laid out as `grouping` places
/// labels at, as PowerPoint offers them: none for a family that offers no
/// position (a 3D bar, line or area plot, an area, doughnut, radar or
/// surface plot), and none outside the end of a stacked or 100% stacked
/// bar (FIX 10297).
pub(super) fn positions(
    kind: ChartKind,
    grouping: Option<PlotGrouping>,
) -> &'static [&'static str] {
    match kind {
        ChartKind::Bar
            if matches!(
                grouping,
                Some(PlotGrouping::Stacked | PlotGrouping::PercentStacked)
            ) =>
        {
            &["ctr", "inEnd", "inBase"]
        }
        ChartKind::Bar => &["ctr", "inEnd", "inBase", "outEnd"],
        ChartKind::Line | ChartKind::Scatter | ChartKind::Bubble | ChartKind::Stock => {
            &["t", "b", "l", "r", "ctr"]
        }
        ChartKind::Pie | ChartKind::Pie3D | ChartKind::OfPie => {
            &["bestFit", "ctr", "inEnd", "outEnd"]
        }
        _ => &[],
    }
}

/// `name` in `dropped`, once.
fn note(dropped: &mut Vec<String>, name: String) {
    if !dropped.contains(&name) {
        dropped.push(name);
    }
}

/// The splice that drops the label position of the labels element at `at`
/// (a `c:dLbls`, or one point's `c:dLbl`) when a `kind` plot laid out as
/// `grouping` places no label there; none when it does, or the element
/// holds no position.
pub(super) fn position(
    tree: &XmlTree,
    at: usize,
    (kind, grouping): (ChartKind, Option<PlotGrouping>),
    dropped: &mut Vec<String>,
) -> Option<Splice> {
    let pos = xml::child(tree, at, C, "dLblPos")?;
    let value = tree.nodes[pos].attr("val").unwrap_or_default().trim();
    if positions(kind, grouping).contains(&value) {
        return None;
    }
    note(dropped, format!("dLblPos {value}"));
    Some((tree.nodes[pos].span.clone(), Vec::new()))
}

/// The splices that drop each child of the point at `at` (a `c:dPt`) a
/// series of a `kind` plot does not draw.
pub(super) fn point(
    tree: &XmlTree,
    at: usize,
    kind: ChartKind,
    dropped: &mut Vec<String>,
) -> Vec<Splice> {
    let holds = order(kind);
    POINT_ONLY
        .iter()
        .filter(|&&name| !holds.contains(&name))
        .filter_map(|&name| {
            let child = xml::child(tree, at, C, name)?;
            note(dropped, format!("dPt {name}"));
            Some((tree.nodes[child].span.clone(), Vec::new()))
        })
        .collect()
}

/// The labels element at `at` (a plot's or a series' `c:dLbls`) as a `kind`
/// plot laid out as `grouping` holds it: its own label position and each
/// point label's dropped where that plot places no label there, everything
/// else kept.
pub(super) fn labels(
    bytes: &[u8],
    tree: &XmlTree,
    at: usize,
    plot: (ChartKind, Option<PlotGrouping>),
    dropped: &mut Vec<String>,
) -> Result<Vec<u8>, LiveError> {
    let mut splices: Vec<Splice> = position(tree, at, plot, dropped).into_iter().collect();
    for label in held::children(tree, at, C, "dLbl") {
        splices.extend(position(tree, label, plot, dropped));
    }
    if splices.is_empty() {
        return Ok(piece(bytes, tree, at).to_vec());
    }
    applied(bytes, tree, at, splices)
}

/// The element a `kind` plot keeps its filtered (hidden) series in, each a
/// series of that family's form.
fn filtered(kind: ChartKind) -> &'static str {
    match kind {
        ChartKind::Bar | ChartKind::Bar3D => "filteredBarSeries",
        ChartKind::Line | ChartKind::Line3D | ChartKind::Stock => "filteredLineSeries",
        ChartKind::Area | ChartKind::Area3D => "filteredAreaSeries",
        ChartKind::Pie | ChartKind::Pie3D | ChartKind::Doughnut | ChartKind::OfPie => {
            "filteredPieSeries"
        }
        ChartKind::Radar => "filteredRadarSeries",
        ChartKind::Scatter => "filteredScatterSeries",
        ChartKind::Bubble => "filteredBubbleSeries",
        ChartKind::Surface | ChartKind::Surface3D => "filteredSurfaceSeries",
    }
}

/// A converted plot's held `c:extLst` at `at` as a `kind` plot holds it:
/// each extension holding filtered series of another family's form (a
/// `c15:filteredBarSeries` in a line plot) dropped and named in `dropped`
/// (FIX 10298), every other extension and byte kept; `None` when no
/// extension is left.
pub(super) fn extensions(
    bytes: &[u8],
    tree: &XmlTree,
    at: usize,
    kind: ChartKind,
    dropped: &mut Vec<String>,
) -> Result<Option<Vec<u8>>, LiveError> {
    let own = filtered(kind);
    let mut splices: Vec<Splice> = Vec::new();
    let mut left = 0_usize;
    for ext in held::children(tree, at, C, "ext") {
        let foreign = tree.nodes[ext]
            .children
            .iter()
            .map(|&child| &tree.nodes[child])
            .find(|node| {
                node.namespace == C15
                    && node.name.starts_with("filtered")
                    && node.name.ends_with("Series")
                    && node.name != own
            });
        match foreign {
            Some(node) => {
                note(dropped, node.name.clone());
                splices.push((tree.nodes[ext].span.clone(), Vec::new()));
            }
            None => left += 1,
        }
    }
    if splices.is_empty() {
        return Ok(Some(piece(bytes, tree, at).to_vec()));
    }
    if left == 0 {
        return Ok(None);
    }
    applied(bytes, tree, at, splices).map(Some)
}
