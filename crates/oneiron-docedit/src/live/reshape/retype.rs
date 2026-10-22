//! Data labels and point formatting retyped to a new family (OF-510, FIX
//! 9276, 9275): a data label position stays where the new family places
//! labels so, and goes where it does not; a point's marker, explosion, 3D
//! bubble, picture or negative inversion goes where the new family draws
//! none. Each label keeps its text and its other settings, each point its
//! fill and line, and every other byte stays. What goes is named, as its
//! chart part names it, for the receipt.
//! Entry: `position`, `point`, `labels`.

use super::families::applied;
use super::retained::order;
use super::*;
use crate::edit::xml::Splice;

/// The point children only some families draw.
const POINT_ONLY: &[&str] = &[
    "invertIfNegative",
    "marker",
    "bubble3D",
    "explosion",
    "pictureOptions",
];

/// The data label positions a `kind` plot places labels at, as PowerPoint
/// offers them: none for a family that offers no position (a 3D bar, line
/// or area plot, an area, doughnut, radar or surface plot).
fn positions(kind: ChartKind) -> &'static [&'static str] {
    match kind {
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
/// (a `c:dLbls`, or one point's `c:dLbl`) when a `kind` plot places no
/// label there; none when it does, or the element holds no position.
pub(super) fn position(
    tree: &XmlTree,
    at: usize,
    kind: ChartKind,
    dropped: &mut Vec<String>,
) -> Option<Splice> {
    let pos = xml::child(tree, at, C, "dLblPos")?;
    let value = tree.nodes[pos].attr("val").unwrap_or_default().trim();
    if positions(kind).contains(&value) {
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
/// plot holds it: its own label position and each point label's dropped
/// where `kind` places no label there, everything else kept.
pub(super) fn labels(
    bytes: &[u8],
    tree: &XmlTree,
    at: usize,
    kind: ChartKind,
    dropped: &mut Vec<String>,
) -> Result<Vec<u8>, LiveError> {
    let mut splices: Vec<Splice> = position(tree, at, kind, dropped).into_iter().collect();
    for label in held::children(tree, at, C, "dLbl") {
        splices.extend(position(tree, label, kind, dropped));
    }
    if splices.is_empty() {
        return Ok(piece(bytes, tree, at).to_vec());
    }
    applied(bytes, tree, at, splices)
}
