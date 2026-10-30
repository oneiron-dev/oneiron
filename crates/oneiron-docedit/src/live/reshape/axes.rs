//! A rewritten chart's axes: a held x axis turned between a category and
//! a value axis, a new pair of axes, and a new depth axis (a 3D line and a
//! surface plot's, and a 3D bar or area plot's standing its series one
//! behind another).
//! Entry: `plot_axes`, `retyped_axis`, `axes`, `ser_axis`.

use super::families;
use super::*;
use crate::live::held::children;
use crate::live::pptx::{ChartPlot, surface};
use std::collections::{BTreeMap, BTreeSet};

/// A value axis's children in schema order.
const VALUE: &[&str] = &[
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
    "crossBetween",
    "majorUnit",
    "minorUnit",
    "dispUnits",
    "extLst",
];

/// A held x axis turned into the other kind of axis, a value axis
/// (`value`) for a scatter or bubble plot or a category axis for a category
/// plot, as a chart type change between them turns it (FIX 8587): its own
/// element renamed (its prefix, attributes and namespace bindings kept), the
/// fields only the other kind holds dropped, that kind's required fields
/// added where it holds none (before a trailing `c:extLst`), and every
/// other child, extension and byte between them kept.
pub(super) fn retyped_axis(
    bytes: &[u8],
    tree: &XmlTree,
    axis: usize,
    value: bool,
    writer: &Writer,
) -> Result<Vec<u8>, LiveError> {
    const CATEGORY: &[&str] = &[
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
        "auto",
        "lblAlgn",
        "lblOffset",
        "tickLblSkip",
        "tickMarkSkip",
        "noMultiLvlLbl",
        "extLst",
    ];
    let flag =
        |name: &str, val: &str| format!(r#"<{} val="{val}"/>"#, writer.el(name)).into_bytes();
    let node = &tree.nodes[axis];
    let (order, entries): (&[&str], Vec<(&str, Vec<u8>)>) = if value {
        let mut entries: Vec<(&str, Vec<u8>)> = [
            "auto",
            "lblAlgn",
            "lblOffset",
            "tickLblSkip",
            "tickMarkSkip",
            "noMultiLvlLbl",
            "baseTimeUnit",
            "majorTimeUnit",
            "minorTimeUnit",
        ]
        .into_iter()
        .map(|name| (name, Vec::new()))
        .collect();
        if xml::child(tree, axis, C, "crossBetween").is_none() {
            entries.push(("crossBetween", flag("crossBetween", "midCat")));
        }
        (VALUE, entries)
    } else {
        let mut entries: Vec<(&str, Vec<u8>)> =
            ["crossBetween", "majorUnit", "minorUnit", "dispUnits"]
                .into_iter()
                .map(|name| (name, Vec::new()))
                .collect();
        for (name, val) in [
            ("auto", "1"),
            ("lblAlgn", "ctr"),
            ("lblOffset", "100"),
            ("noMultiLvlLbl", "0"),
        ] {
            if xml::child(tree, axis, C, name).is_none() {
                entries.push((name, flag(name, val)));
            }
        }
        (CATEGORY, entries)
    };
    let mut splices = families::written(bytes, tree, axis, order, &entries, |name| name);
    let local = if value { "valAx" } else { "catAx" };
    splices.extend(xml::rename_element(
        node,
        &xml::qualify(xml::prefix(node), local),
    ));
    families::applied(bytes, tree, axis, splices)
}

/// A held value axis crossing its x axis at the categories (`midCat`), as
/// a plot converted to a surface plots on it (FIX 10299, as new surface
/// axes do, FIX 9376): its `c:crossBetween` written over, every other child
/// and byte kept; its own bytes when it crosses there already or is no
/// value axis.
pub(super) fn mid_cat_axis(
    bytes: &[u8],
    tree: &XmlTree,
    axis: usize,
    writer: &Writer,
) -> Result<Vec<u8>, LiveError> {
    let crosses = xml::child(tree, axis, C, "crossBetween")
        .and_then(|at| tree.nodes[at].attr("val"))
        .map(str::trim);
    if !tree.nodes[axis].is(C, "valAx") || crosses == Some("midCat") {
        return Ok(bytes[tree.nodes[axis].span.clone()].to_vec());
    }
    let entry = format!(r#"<{} val="midCat"/>"#, writer.el("crossBetween")).into_bytes();
    let splices = families::written(
        bytes,
        tree,
        axis,
        VALUE,
        &[("crossBetween", entry)],
        |name| name,
    );
    families::applied(bytes, tree, axis, splices)
}

/// A new depth (series) axis under id `id`, crossing the value axis
/// `cross`, as a 3D plot that stands its series one behind another needs.
pub(super) fn ser_axis(writer: &Writer, id: u32, cross: u32) -> String {
    let el = |name: &str| writer.el(name);
    let flag = |name: &str, val: &str| format!(r#"<{} val="{val}"/>"#, el(name));
    format!(
        "<{sa}>{}<{s}>{}</{s}>{}{}{}{}{}{}{}</{sa}>",
        flag("axId", &id.to_string()),
        flag("orientation", "minMax"),
        flag("delete", "0"),
        flag("axPos", "b"),
        flag("majorTickMark", "out"),
        flag("minorTickMark", "none"),
        flag("tickLblPos", "nextTo"),
        flag("crossAx", &cross.to_string()),
        flag("crosses", "autoZero"),
        sa = el("serAx"),
        s = el("scaling"),
    )
}

/// A new pair of axes under ids `fresh` and `fresh + 1`, crossing each
/// other: an x axis (a value axis for a scatter plot, `value`, else a
/// category axis) and a value axis, crossing between categories, or at
/// them for a scatter plot and a surface (`mid_cat`, as Office writes a
/// surface's, FIX 9376). A `secondary` pair, beside a plot that already has
/// axes, hides its x axis and puts its value axis on the right.
pub(super) fn axes(
    writer: &Writer,
    fresh: u32,
    (value, mid_cat): (bool, bool),
    secondary: bool,
) -> String {
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
    let between = if value || mid_cat {
        "midCat"
    } else {
        "between"
    };
    format!(
        "{x_axis}<{va}>{}{}</{va}>",
        common(y, "0", side, &gridlines, x, crosses),
        flag("crossBetween", between),
        va = el("valAx"),
    )
}

/// The axes a chart rewrite's plots plot on: the plot area's held axes
/// (each id and node), each target plot's axis ids, each target's held
/// plot's own ids, the held x axes that turn between a category and a value
/// axis, the held value axes a plot converted to a surface crosses at the
/// categories, and the new axes' XML.
pub(super) struct PlotAxes {
    pub(super) held: Vec<(u32, usize)>,
    pub(super) ids: Vec<Vec<u32>>,
    pub(super) kept: Vec<Vec<u32>>,
    pub(super) retyped: BTreeMap<u32, bool>,
    pub(super) mid_cat: BTreeSet<u32>,
    pub(super) new: String,
}

/// The axes each target plot (`targets`, over the held `plots` of the plot
/// area `area`) plots on, as its family lays them out (`nths`, each
/// target's place among its family's, and `settings`, the model's plot
/// settings, give its grouping): a held plot's own, another plot's of the
/// same kind, or a new pair, each id above every id the chart holds; a 3D
/// plot that stands its series one behind another a depth axis too, a 3D
/// pie none. A held x axis turns between a category and a value axis with
/// its plot, and a held value axis a plot converted to a surface keeps
/// crosses at the categories, as a new surface's does (FIX 10299).
pub(super) fn plot_axes(
    tree: &XmlTree,
    area: usize,
    (plots, targets): (&[(ChartKind, usize)], &[PlotTarget]),
    (nths, settings): (&[u32], &[ChartPlot]),
    writer: &Writer,
) -> PlotAxes {
    let held_axes: Vec<(u32, usize)> = tree.nodes[area]
        .children
        .iter()
        .copied()
        .filter(|&at| is_axis(&tree.nodes[at]))
        .filter_map(|at| Some((int(tree, at, "axId")?, at)))
        .collect();
    let mut depth_axes: BTreeSet<u32> = held_axes
        .iter()
        .filter(|&&(_, at)| tree.nodes[at].name == "serAx")
        .map(|&(id, _)| id)
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
    let mut mid_cat: BTreeSet<u32> = BTreeSet::new();
    let mut new_axes = String::new();
    let mut ids_of: Vec<Vec<u32>> = Vec::with_capacity(targets.len());
    let mut held_ids: Vec<Vec<u32>> = Vec::with_capacity(targets.len());
    for (at_target, target) in targets.iter().enumerate() {
        let wants_value = target.kind.draws_x();
        let same = target.held.filter(|&at| plots[at].0 == target.kind);
        let grouping = families::grouping(
            tree,
            same.map(|at| plots[at].1),
            target.kind,
            settings,
            nths[at_target],
        );
        let depth = target.kind.depth_axis(grouping);
        let kept: Vec<u32> = target
            .held
            .filter(|&at| plots[at].0.has_axes())
            .map(|at| {
                children(tree, plots[at].1, C, "axId")
                    .filter_map(|id| tree.nodes[id].attr("val")?.trim().parse().ok())
                    .collect()
            })
            .unwrap_or_default();
        held_ids.push(kept.clone());
        let fits = |ids: &&Vec<u32>| {
            ids.len() >= 2
                && value_x.get(&ids[0]).copied().unwrap_or(false) == wants_value
                && ids.iter().any(|id| depth_axes.contains(id)) == depth
        };
        // A line plot beside a stock plot (the series a stock plot has no
        // price for) plots on the stock plot's axes.
        let stock = targets[..at_target]
            .iter()
            .zip(&ids_of)
            .filter(|(other, _)| target.kind == ChartKind::Line && other.kind == ChartKind::Stock)
            .map(|(_, ids)| ids)
            .find(&fits);
        let shared = stock.or_else(|| ids_of.iter().find(&fits)).cloned();
        let ids = if !target.kind.has_axes() {
            Vec::new()
        } else if kept.len() >= 2 {
            let x = kept[0];
            if value_x.get(&x).copied().unwrap_or(false) != wants_value {
                retyped.insert(x, wants_value);
                value_x.insert(x, wants_value);
            }
            let converted = target.held.is_some_and(|at| !surface(plots[at].0));
            if surface(target.kind) && converted {
                mid_cat.insert(kept[1]);
            }
            let mut ids: Vec<u32> = kept
                .iter()
                .copied()
                .filter(|id| depth || !depth_axes.contains(id))
                .collect();
            if depth && !ids.iter().any(|id| depth_axes.contains(id)) {
                ids.truncate(2);
                new_axes.push_str(&ser_axis(writer, fresh, ids[1]));
                depth_axes.insert(fresh);
                ids.push(fresh);
                fresh = fresh.saturating_add(1);
            }
            ids
        } else if let Some(ids) = shared {
            ids
        } else {
            let secondary = ids_of.iter().any(|ids| !ids.is_empty());
            new_axes.push_str(&axes(
                writer,
                fresh,
                (wants_value, surface(target.kind)),
                secondary,
            ));
            value_x.insert(fresh, wants_value);
            let mut ids = vec![fresh, fresh.saturating_add(1)];
            if depth {
                let id = fresh.saturating_add(2);
                new_axes.push_str(&ser_axis(writer, id, ids[1]));
                depth_axes.insert(id);
                ids.push(id);
            }
            fresh = fresh.saturating_add(3);
            ids
        };
        ids_of.push(ids);
    }
    PlotAxes {
        held: held_axes,
        ids: ids_of,
        kept: held_ids,
        retyped,
        mid_cat,
        new: new_axes,
    }
}
