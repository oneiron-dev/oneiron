//! What a retained element is written as, in live-model terms: a shape's or
//! connector's preset, a connector's glue, a table's cell text, a classic
//! chart's categories and series, and a picture's media digest. The import
//! records it on each node, and the export projector reads it again to write
//! only what the live model changed.

use super::LiveError;
use super::pptx::{ChartKind, ChartSeries, ConnectorEnd, NodeId, NodePayload};
use crate::deck::{ShapeKind, ShapeView};
use crate::design_plan::Cell;
use crate::edit::geometry::{glue_of, preset_of};
use crate::edit::xml::{self, A, P, R};
use crate::edit::{ConnectorPreset, Digest, Preset};
use crate::native_patch::{ChartData, chart_data};
use crate::ooxml::XmlTree;
use crate::retained_opc::Package;

const C: &str = "http://schemas.openxmlformats.org/drawingml/2006/chart";
const FRAME_DATA: &[(&str, &str)] = &[(A, "graphic"), (A, "graphicData")];

/// A slide part's parsed tree; [`ShapeView::node`] indexes into it.
pub(crate) fn slide_tree(package: &Package, part: &str) -> Result<XmlTree, LiveError> {
    Ok(xml::read(package, part)?.1)
}

/// A shape's preset, when it is one the live deck writes. Custom geometry
/// and other presets read as none and stay as written.
pub(crate) fn shape_preset(tree: &XmlTree, shape: &ShapeView) -> Option<Preset> {
    if shape.kind != ShapeKind::Shape {
        return None;
    }
    preset_of(tree, shape.node.index).and_then(Preset::from_name)
}

/// A retained element's payload: a connector's geometry and glue (each end
/// through `node_of`, the live node holding a native id on the slide), a
/// table's cells, or a classic bar, line or pie chart's data. A picture's
/// media has no engine asset identity, and a connector or chart outside the
/// written set or one the chart reader refuses reads as none: they stay in
/// the retained markup.
pub(crate) fn payload(
    package: &Package,
    part: &str,
    tree: &XmlTree,
    shape: &ShapeView,
    node_of: impl Fn(u32) -> Option<NodeId>,
) -> Option<NodePayload> {
    let at = shape.node.index;
    match shape.kind {
        ShapeKind::Connector => {
            let preset = ConnectorPreset::from_name(preset_of(tree, at)?)?;
            let (start, end) = glue_of(tree, at);
            let end_of = |glue: Option<(u32, u32)>| {
                let (native, site) = glue?;
                Some(ConnectorEnd {
                    node: node_of(native)?,
                    site,
                })
            };
            Some(NodePayload::Connector {
                preset,
                start: end_of(start),
                end: end_of(end),
            })
        }
        ShapeKind::GraphicFrame => {
            if let Some(cells) = table_cells(tree, at) {
                let (header, rows) = cells.split_first()?;
                return Some(NodePayload::Table {
                    header: header.clone(),
                    rows: rows
                        .iter()
                        .map(|row| {
                            row.iter()
                                .map(|text| (!text.is_empty()).then(|| text.clone()))
                                .collect()
                        })
                        .collect(),
                });
            }
            let chart = chart_part(package, part, tree, at)?;
            let family = chart_family(package, &chart)?;
            chart_payload(family, &chart_data(package, &chart).ok()?)
        }
        _ => None,
    }
}

fn children<'t>(
    tree: &'t XmlTree,
    at: usize,
    ns: &'t str,
    name: &'t str,
) -> impl Iterator<Item = usize> + 't {
    tree.nodes[at]
        .children
        .iter()
        .copied()
        .filter(move |&child| tree.nodes[child].is(ns, name))
}

/// A table frame's rows of cell text, header row first, each cell read as
/// `NativeEdit::SetTableCell` reads it: the `a:t` text of each paragraph,
/// joined by `\n`. `None` when the frame holds no table.
pub(crate) fn table_cells(tree: &XmlTree, frame: usize) -> Option<Vec<Vec<String>>> {
    let data = xml::path(tree, frame, FRAME_DATA)?;
    let tbl = xml::child(tree, data, A, "tbl")?;
    Some(
        children(tree, tbl, A, "tr")
            .map(|tr| {
                children(tree, tr, A, "tc")
                    .map(|tc| cell_text(tree, tc))
                    .collect()
            })
            .collect(),
    )
}

fn cell_text(tree: &XmlTree, tc: usize) -> String {
    let Some(body) = xml::child(tree, tc, A, "txBody") else {
        return String::new();
    };
    children(tree, body, A, "p")
        .map(|paragraph| {
            let mut text = String::new();
            texts(tree, paragraph, &mut text);
            text
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn texts(tree: &XmlTree, at: usize, out: &mut String) {
    for &child in &tree.nodes[at].children {
        let node = &tree.nodes[child];
        if node.is(A, "t") {
            out.push_str(&node.text);
        } else {
            texts(tree, child, out);
        }
    }
}

/// The chart part a chart frame's `c:chart` relates.
pub(crate) fn chart_part(
    package: &Package,
    part: &str,
    tree: &XmlTree,
    frame: usize,
) -> Option<String> {
    let data = xml::path(tree, frame, FRAME_DATA)?;
    let id = tree.nodes[xml::child(tree, data, C, "chart")?].attr_ns(R, "id")?;
    let kind = format!("{R}/chart");
    package
        .relationships(part)
        .ok()?
        .into_iter()
        .find(|rel| rel.id == id && !rel.external && rel.kind == kind)
        .map(|rel| rel.target)
}

/// The one classic family a chart part plots, when it plots exactly one the
/// live deck writes.
pub(crate) fn chart_family(package: &Package, chart: &str) -> Option<ChartKind> {
    let (_, tree) = xml::read(package, chart).ok()?;
    let plot = xml::path(&tree, 0, &[(C, "chart"), (C, "plotArea")])?;
    let mut families = tree.nodes[plot]
        .children
        .iter()
        .map(|&at| &tree.nodes[at])
        .filter(|node| node.namespace == C && node.name.ends_with("Chart"));
    let family = families.next()?;
    if families.next().is_some() {
        return None;
    }
    match family.name.as_str() {
        "barChart" => Some(ChartKind::Bar),
        "lineChart" => Some(ChartKind::Line),
        "pieChart" => Some(ChartKind::Pie),
        _ => None,
    }
}

/// A chart's data as the live model holds it: one category list every
/// series shares, each series' name and numeric values, all from their
/// caches. A series with a literal sequence, its own categories or a text
/// value has no live form.
fn chart_payload(family: ChartKind, data: &ChartData) -> Option<NodePayload> {
    let mut categories: Option<Vec<String>> = None;
    let mut series = Vec::with_capacity(data.series.len());
    for line in &data.series {
        let held: Vec<String> = line.categories.as_ref()?.cache.iter().map(label).collect();
        if *categories.get_or_insert_with(|| held.clone()) != held {
            return None;
        }
        let values = line
            .values
            .as_ref()?
            .cache
            .iter()
            .map(|cell| match cell {
                Cell::Number(value) => serde_json::Number::from_f64(*value).map(Some),
                Cell::Missing => Some(None),
                Cell::Text(_) | Cell::Date(_) => None,
            })
            .collect::<Option<Vec<_>>>()?;
        series.push(ChartSeries {
            name: label(line.name.as_ref()?.cache.first()?),
            values,
        });
    }
    Some(NodePayload::Chart {
        family,
        categories: categories?,
        series,
    })
}

/// A category or series-name cell as live-model text.
pub(crate) fn label(cell: &Cell) -> String {
    match cell {
        Cell::Text(text) | Cell::Date(text) => text.clone(),
        Cell::Number(value) => value.to_string(),
        Cell::Missing => String::new(),
    }
}

/// The digest of the media a picture shows.
pub(crate) fn picture_media(
    package: &Package,
    part: &str,
    tree: &XmlTree,
    picture: usize,
) -> Option<Digest> {
    let blip = xml::path(tree, picture, &[(P, "blipFill"), (A, "blip")])?;
    let embed = tree.nodes[blip].attr_ns(R, "embed")?;
    let rel = package
        .relationships(part)
        .ok()?
        .into_iter()
        .find(|rel| rel.id == embed && !rel.external)?;
    Some(Digest::of(&package.part(&rel.target).ok()??))
}
