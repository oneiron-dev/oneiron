//! A rewritten chart's plots: a kept plot with its series replaced, and a
//! plot written fresh in its family.
//! Entry: `kept_plot`, `fresh_plot`.

use super::*;

/// A kept plot with its series replaced where they stood.
pub(super) fn kept_plot(bytes: &[u8], tree: &XmlTree, plot: usize, sers: &[u8]) -> Vec<u8> {
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
pub(super) fn fresh_plot(kind: ChartKind, writer: &Writer, sers: &[u8], ids: &[u32]) -> Vec<u8> {
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
