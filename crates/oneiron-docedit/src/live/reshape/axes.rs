//! A rewritten chart's axes: a held x axis turned between a category and
//! a value axis, and a new pair of axes.
//! Entry: `retyped_axis`, `axes`.

use super::*;

/// A held x axis turned into the other kind of axis, a value axis
/// (`value`) for a scatter plot or a category axis for a category plot, as
/// a chart type change between them turns it: the elements both kinds hold
/// keep their bytes, then that kind's own defaults follow.
pub(super) fn retyped_axis(
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
pub(super) fn axes(writer: &Writer, fresh: u32, value: bool, secondary: bool) -> String {
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
