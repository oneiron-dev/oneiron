//! A surviving series written over its own retained XML (OF-510, FIX 8594),
//! in its own plot or moved to another, of its family or another: its
//! `c:idx` and `c:order` values, name, categories or x values, values and
//! bubble sizes written in place, its data points' formatting and labels
//! carried to their points' new places, the children only its old family
//! holds dropped when its family changes (its points' and labels' too,
//! each label's text and other settings kept, FIX 9276), and everything
//! else (its attributes, extensions, unknown children and the bytes
//! between them) kept. A moved series declares the namespace bindings its
//! bytes use that its old plot declared. A template is only for a
//! genuinely new series ([`series::fresh`]).
//! Entry: `retained`.

use super::families::{applied, bit, written};
use super::retype;
use super::series::bindings;
use super::*;
use crate::edit::xml::Splice;

/// A series' children in schema order for a `kind` plot; `cat` and `val`
/// stand for `xVal` and `yVal` too.
pub(super) fn order(kind: ChartKind) -> &'static [&'static str] {
    match kind {
        ChartKind::Bar | ChartKind::Bar3D => &[
            "idx",
            "order",
            "tx",
            "spPr",
            "invertIfNegative",
            "pictureOptions",
            "dPt",
            "dLbls",
            "trendline",
            "errBars",
            "cat",
            "val",
            "shape",
            "extLst",
        ],
        ChartKind::Line | ChartKind::Line3D | ChartKind::Scatter | ChartKind::Stock => &[
            "idx",
            "order",
            "tx",
            "spPr",
            "marker",
            "dPt",
            "dLbls",
            "trendline",
            "errBars",
            "cat",
            "val",
            "smooth",
            "extLst",
        ],
        ChartKind::Pie | ChartKind::Pie3D | ChartKind::Doughnut | ChartKind::OfPie => &[
            "idx",
            "order",
            "tx",
            "spPr",
            "explosion",
            "dPt",
            "dLbls",
            "cat",
            "val",
            "extLst",
        ],
        ChartKind::Area | ChartKind::Area3D => &[
            "idx",
            "order",
            "tx",
            "spPr",
            "pictureOptions",
            "dPt",
            "dLbls",
            "trendline",
            "errBars",
            "cat",
            "val",
            "extLst",
        ],
        ChartKind::Radar => &[
            "idx", "order", "tx", "spPr", "marker", "dPt", "dLbls", "cat", "val", "extLst",
        ],
        ChartKind::Bubble => &[
            "idx",
            "order",
            "tx",
            "spPr",
            "invertIfNegative",
            "dPt",
            "dLbls",
            "trendline",
            "errBars",
            "cat",
            "val",
            "bubbleSize",
            "bubble3D",
            "extLst",
        ],
        ChartKind::Surface | ChartKind::Surface3D => {
            &["idx", "order", "tx", "spPr", "cat", "val", "extLst"]
        }
    }
}

/// The series children only some families hold.
const FAMILY_ONLY: &[&str] = &[
    "invertIfNegative",
    "pictureOptions",
    "marker",
    "explosion",
    "trendline",
    "errBars",
    "shape",
    "smooth",
    "bubbleSize",
    "bubble3D",
];

/// A data labels element's children in schema order.
const LABELS: &[&str] = &[
    "dLbl",
    "delete",
    "numFmt",
    "spPr",
    "txPr",
    "dLblPos",
    "showLegendKey",
    "showVal",
    "showCatName",
    "showSerName",
    "showPercent",
    "showBubbleSize",
    "separator",
    "showLeaderLines",
    "leaderLines",
    "extLst",
];

/// A series child as the slot it stands for: x values for categories, y
/// values for values.
fn alias(name: &str) -> &str {
    match name {
        "xVal" => "cat",
        "yVal" => "val",
        other => other,
    }
}

/// What a surviving series writes: its name, its category (or x) slot and
/// value slot, a bubble series' size slot, its 3D bubble setting, and the
/// line and marker it takes on entering a stock plot.
pub(super) struct Slots<'a> {
    pub(super) tx: &'a str,
    pub(super) cat: &'a str,
    pub(super) val: &'a str,
    pub(super) size: &'a str,
    pub(super) bubble_3d: Option<bool>,
    pub(super) stock: Option<(Vec<u8>, Vec<u8>)>,
}

/// The survivor `ser`, drawn in a `from` plot, written as a series of a
/// `to` plot (`moved` out of the plot element that held it): its `idx`
/// and `order` values set, its slots written in place (a slot it lacks
/// inserted in schema order), its points' formatting and labels carried
/// ([`Points`]), and, when its family changes, the children `to` does not
/// hold dropped, and each data label position and point child `to` does
/// not hold too ([`retype`]), named in `dropped`. Everything else keeps its
/// bytes.
#[allow(clippy::too_many_arguments)]
pub(super) fn retained(
    bytes: &[u8],
    tree: &XmlTree,
    ser: usize,
    (idx, place): (u32, u32),
    writer: &Writer,
    (from, to, moved): (ChartKind, ChartKind, bool),
    slots: &Slots<'_>,
    points: &Points,
    dropped: &mut Vec<String>,
) -> Result<Vec<u8>, LiveError> {
    let node = &tree.nodes[ser];
    let changed = from != to;
    let flag = |name: &str, value: &str| format!(r#"<{} val="{value}"/>"#, writer.el(name));
    let mut entries: Vec<(&str, Vec<u8>)> = vec![
        ("tx", slots.tx.as_bytes().to_vec()),
        ("cat", slots.cat.as_bytes().to_vec()),
        ("val", slots.val.as_bytes().to_vec()),
    ];
    for (name, value) in [("idx", idx), ("order", place)] {
        if xml::child(tree, ser, C, name).is_none() {
            entries.push((name, flag(name, &value.to_string()).into_bytes()));
        }
    }
    if to == ChartKind::Bubble {
        entries.push(("bubbleSize", slots.size.as_bytes().to_vec()));
        if let Some(on) = slots.bubble_3d
            && held::flag(tree, ser, "bubble3D") != Some(on)
        {
            entries.push(("bubble3D", flag("bubble3D", bit(on)).into_bytes()));
        }
    }
    // A surface series holds no point formatting or labels.
    let holds = |name: &str| order(to).contains(&name);
    if xml::child(tree, ser, C, "dPt").is_some() {
        let points = if holds("dPt") {
            let mut retyped = |at: usize| -> Vec<Splice> {
                if changed {
                    retype::point(tree, at, to, dropped)
                } else {
                    Vec::new()
                }
            };
            carried(bytes, tree, &node.children, "dPt", points, &mut retyped)?
        } else {
            Vec::new()
        };
        entries.push(("dPt", points));
    }
    let labels = xml::child(tree, ser, C, "dLbls");
    if labels.is_some() && !holds("dLbls") {
        entries.push(("dLbls", Vec::new()));
    }
    if changed {
        for name in FAMILY_ONLY {
            if !order(to).contains(name) && xml::child(tree, ser, C, name).is_some() {
                entries.push((*name, Vec::new()));
            }
        }
    }
    // A series entering a stock plot draws no line and no marker but on its
    // close; one leaving it takes its new plot's own again.
    if let Some((line, marker)) = &slots.stock {
        entries.push(("spPr", line.clone()));
        entries.push(("marker", marker.clone()));
    } else if from == ChartKind::Stock && to != ChartKind::Stock {
        entries.push(("spPr", Vec::new()));
        entries.push(("marker", Vec::new()));
    }
    let mut splices = written(bytes, tree, ser, order(to), &entries, alias);
    for (name, value) in [("idx", idx), ("order", place)] {
        if let Some(at) = xml::child(tree, ser, C, name) {
            splices.push(xml::set_attribute(
                bytes,
                &tree.nodes[at],
                "val",
                &value.to_string(),
            ));
        }
    }
    if let Some(labels) = labels.filter(|&at| holds("dLbls") && !tree.nodes[at].empty) {
        // Each point label's position, and the series', stays where `to`
        // places labels so (FIX 9276).
        let mut retyped = |at: usize| -> Vec<Splice> {
            if changed {
                retype::position(tree, at, to, dropped)
                    .into_iter()
                    .collect()
            } else {
                Vec::new()
            }
        };
        let mut inner = vec![(
            "dLbl",
            carried(
                bytes,
                tree,
                &tree.nodes[labels].children,
                "dLbl",
                points,
                &mut retyped,
            )?,
        )];
        if changed && retype::position(tree, labels, to, dropped).is_some() {
            inner.push(("dLblPos", Vec::new()));
        }
        // A label element the labels do not hold is not added.
        inner.retain(|(name, value)| {
            !value.is_empty() || xml::child(tree, labels, C, name).is_some()
        });
        splices.extend(written(bytes, tree, labels, LABELS, &inner, |name| name));
    }
    if moved {
        let at = node.span.start + 1 + node.qualified.len();
        let declared = bindings(bytes, tree, ser);
        if !declared.is_empty() {
            splices.push((at..at, declared.into_bytes()));
        }
    }
    applied(bytes, tree, ser, splices)
}
