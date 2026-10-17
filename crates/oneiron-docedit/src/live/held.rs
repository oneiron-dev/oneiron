//! What a retained element is written as, in live-model terms: a shape's
//! preset or custom geometry, a connector's preset and glue, a table's cell
//! text, a chart's plots, categories and series read from its caches, a
//! SmartArt's text outline, an OLE object's program id and preview, and a
//! picture's media identity. The import records it on each node, and the
//! export projector reads it again to write only what the live model changed.

use super::LiveError;
use super::pptx::{
    ChartKind, ChartSeries, ChartSource, ConnectorEnd, HeldMedia, NodeId, NodePayload, SmartArtNode,
};
use crate::deck::{ShapeKind, ShapeView};
use crate::design_plan::Cell;
use crate::edit::geometry::{glue_of, preset_of};
use crate::edit::xml::{self, A, P, R};
use crate::edit::{ConnectorPreset, Digest, Preset};
use crate::native_patch::chart_data;
use crate::ooxml::XmlTree;
use crate::retained_opc::Package;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const C: &str = "http://schemas.openxmlformats.org/drawingml/2006/chart";
const DGM: &str = "http://schemas.openxmlformats.org/drawingml/2006/diagram";
const OLE: &str = "http://schemas.openxmlformats.org/presentationml/2006/ole";
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

/// A retained element's payload: a shape's custom geometry, a picture's
/// media, a connector's preset and glue (each end through `node_of`, the
/// live node holding a native id on the slide), a table's cells, a chart's
/// data, a SmartArt's text outline, or an OLE object's program id and
/// preview. Anything else, and a chart the reader cannot read, reads as none
/// and stays in the retained markup.
pub(crate) fn payload(
    package: &Package,
    part: &str,
    tree: &XmlTree,
    shape: &ShapeView,
    node_of: impl Fn(u32) -> Option<NodeId>,
) -> Option<NodePayload> {
    let at = shape.node.index;
    match shape.kind {
        ShapeKind::Shape => {
            let geometry = xml::path(tree, at, &[(P, "spPr"), (A, "custGeom")])?;
            let paths = xml::child(tree, geometry, A, "pathLst")
                .map_or(0, |list| children(tree, list, A, "path").count());
            Some(NodePayload::CustomGeometry {
                paths: u32::try_from(paths).unwrap_or(u32::MAX),
            })
        }
        ShapeKind::Picture => Some(NodePayload::HeldPicture {
            media: picture_media(package, part, tree, at)?,
        }),
        ShapeKind::Connector => {
            let preset = preset_of(tree, at).and_then(ConnectorPreset::from_name);
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
            let data = xml::path(tree, at, FRAME_DATA)?;
            match tree.nodes[data].attr("uri")? {
                C => chart(package, &chart_part(package, part, tree, at)?),
                DGM => smart_art(package, part, tree, data),
                OLE => ole(package, part, tree, at),
                _ => None,
            }
        }
        ShapeKind::Group => None,
    }
}

pub(crate) fn children<'t>(
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

/// Nodes inside `at`, in document order.
pub(crate) fn within(tree: &XmlTree, at: usize) -> impl Iterator<Item = usize> + '_ {
    let end = tree.nodes[at].span.end;
    (at + 1..tree.nodes.len()).take_while(move |&index| tree.nodes[index].span.start < end)
}

/// A table frame's `a:tbl`.
pub(crate) fn table_of(tree: &XmlTree, frame: usize) -> Option<usize> {
    let data = xml::path(tree, frame, FRAME_DATA)?;
    xml::child(tree, data, A, "tbl")
}

/// A table frame's rows of cell text, header row first, each cell read as
/// `NativeEdit::SetTableCell` reads it: the `a:t` text of each paragraph,
/// joined by `\n`. `None` when the frame holds no table.
pub(crate) fn table_cells(tree: &XmlTree, frame: usize) -> Option<Vec<Vec<String>>> {
    let tbl = table_of(tree, frame)?;
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
    xml::child(tree, tc, A, "txBody").map_or_else(String::new, |body| paragraphs(tree, body))
}

/// The `a:t` text of each `a:p` under `body`, joined by `\n`.
fn paragraphs(tree: &XmlTree, body: usize) -> String {
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

/// The plot family a `c:plotArea` child is, when the live deck reads it.
pub(crate) fn plot_family(name: &str) -> Option<ChartKind> {
    Some(match name {
        "barChart" => ChartKind::Bar,
        "lineChart" => ChartKind::Line,
        "pieChart" => ChartKind::Pie,
        "areaChart" => ChartKind::Area,
        "scatterChart" => ChartKind::Scatter,
        "doughnutChart" => ChartKind::Doughnut,
        "radarChart" => ChartKind::Radar,
        _ => return None,
    })
}

/// A chart part's plots in document order: each family and its element.
/// `None` when a plot is one the live deck does not read.
pub(crate) fn plots(tree: &XmlTree) -> Option<(usize, Vec<(ChartKind, usize)>)> {
    let area = xml::path(tree, 0, &[(C, "chart"), (C, "plotArea")])?;
    let plots = tree.nodes[area]
        .children
        .iter()
        .copied()
        .filter(|&at| tree.nodes[at].namespace == C && tree.nodes[at].name.ends_with("Chart"))
        .map(|at| Some((plot_family(&tree.nodes[at].name)?, at)))
        .collect::<Option<Vec<_>>>()?;
    (!plots.is_empty()).then_some((area, plots))
}

/// One series sequence as its cache or literal holds it.
pub(crate) struct Points {
    pub(crate) cells: Vec<Cell>,
    pub(crate) numeric: bool,
    /// The cell reference, for a `c:strRef` or `c:numRef`.
    pub(crate) formula: Option<String>,
}

/// The sequence under a `c:tx`, `c:cat`, `c:val`, `c:xVal` or `c:yVal`
/// slot: a reference's cache, a literal, or a name's `c:v`. `None` when it
/// is unreadable (a multi-level reference, a reference without a cache, a
/// point outside its count).
pub(crate) fn points(tree: &XmlTree, slot: usize) -> Option<Points> {
    for &child in &tree.nodes[slot].children {
        let node = &tree.nodes[child];
        if node.namespace != C {
            continue;
        }
        let (numeric, data, formula) = match node.name.as_str() {
            "v" => {
                return Some(Points {
                    cells: vec![Cell::Text(node.text.clone())],
                    numeric: false,
                    formula: None,
                });
            }
            "strRef" => (false, xml::child(tree, child, C, "strCache")?, true),
            "numRef" => (true, xml::child(tree, child, C, "numCache")?, true),
            "strLit" => (false, child, false),
            "numLit" => (true, child, false),
            _ => continue,
        };
        let count = xml::child(tree, data, C, "ptCount")
            .and_then(|at| tree.nodes[at].attr("val")?.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let mut cells = vec![Cell::Missing; count];
        for pt in children(tree, data, C, "pt") {
            let idx: usize = tree.nodes[pt].attr("idx")?.trim().parse().ok()?;
            let text = xml::child(tree, pt, C, "v")
                .map_or_else(String::new, |v| tree.nodes[v].text.clone());
            *cells.get_mut(idx)? = if numeric {
                Cell::Number(text.trim().parse().ok()?)
            } else {
                Cell::Text(text)
            };
        }
        let formula = if formula {
            Some(
                tree.nodes[xml::child(tree, child, C, "f")?]
                    .text
                    .trim()
                    .to_owned(),
            )
        } else {
            None
        };
        return Some(Points {
            cells,
            numeric,
            formula,
        });
    }
    None
}

/// A series slot's points: `Some(None)` when the series has no such slot,
/// `None` when it has one the reader cannot read.
fn slot(tree: &XmlTree, ser: usize, name: &str) -> Option<Option<Points>> {
    match xml::child(tree, ser, C, name) {
        None => Some(None),
        Some(at) => points(tree, at).map(Some),
    }
}

fn numbers(cells: &[Cell]) -> Option<Vec<Option<serde_json::Number>>> {
    cells
        .iter()
        .map(|cell| match cell {
            Cell::Number(value) => serde_json::Number::from_f64(*value).map(Some),
            Cell::Missing => Some(None),
            Cell::Text(_) | Cell::Date(_) => None,
        })
        .collect()
}

/// A chart part's data as the live model holds it, read from its caches
/// and literals: the first plot's family, the categories every category
/// series shares, and each series' name and values, with a combo chart's
/// plot family and a scatter series' x values. A series with its own
/// categories, a text value, or a plot the reader does not read leaves the
/// chart without a live form.
pub(crate) fn chart(package: &Package, chart: &str) -> Option<NodePayload> {
    let (_, tree) = xml::read(package, chart).ok()?;
    let (_, plots) = plots(&tree)?;
    let family = plots.first()?.0;
    let combo = plots.len() > 1;
    let mut categories: Option<Vec<String>> = None;
    let mut series = Vec::new();
    let mut referenced = false;
    for &(plot, at) in &plots {
        let scatter = plot == ChartKind::Scatter;
        let (cat, val) = if scatter {
            ("xVal", "yVal")
        } else {
            ("cat", "val")
        };
        for ser in children(&tree, at, C, "ser") {
            let name = slot(&tree, ser, "tx")?;
            let held = slot(&tree, ser, cat)?;
            let values = slot(&tree, ser, val)?;
            referenced |= [&name, &held, &values]
                .into_iter()
                .flatten()
                .any(|points| points.formula.is_some());
            let values = values.map_or(Some(Vec::new()), |points| numbers(&points.cells))?;
            let x = match held {
                Some(points) if scatter && points.numeric => {
                    let mut x = numbers(&points.cells)?;
                    if x.len() < values.len() {
                        x.resize(values.len(), None);
                    }
                    Some(x)
                }
                Some(points) if !scatter => {
                    let held: Vec<String> = points.cells.iter().map(label).collect();
                    if *categories.get_or_insert_with(|| held.clone()) != held {
                        return None;
                    }
                    None
                }
                _ => None,
            };
            series.push(ChartSeries {
                name: name
                    .and_then(|points| points.cells.first().map(label))
                    .unwrap_or_default(),
                values,
                family: combo.then_some(plot),
                x,
            });
        }
    }
    let mut categories = categories.unwrap_or_default();
    // A category series holds no more values than there are categories.
    let longest = series
        .iter()
        .filter(|line| line.family.unwrap_or(family) != ChartKind::Scatter)
        .map(|line| line.values.len())
        .max()
        .unwrap_or(0);
    if !categories.is_empty() && categories.len() < longest {
        categories.resize(longest, String::new());
    }
    let source = if !referenced {
        ChartSource::Literal
    } else if chart_data(package, chart).is_ok() {
        ChartSource::Workbook
    } else {
        ChartSource::Cached
    };
    Some(NodePayload::Chart {
        family,
        categories,
        series,
        source,
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

/// A SmartArt frame's text outline from its data part: each content point
/// (a node or an assistant) in the order its parent lists it, at its depth
/// below the document point. A point no parent lists follows at level 0.
fn smart_art(package: &Package, part: &str, tree: &XmlTree, data: usize) -> Option<NodePayload> {
    let ids = xml::child(tree, data, DGM, "relIds")?;
    let dm = tree.nodes[ids].attr_ns(R, "dm")?;
    let rel = package
        .relationships(part)
        .ok()?
        .into_iter()
        .find(|rel| rel.id == dm && !rel.external)?;
    let (_, model) = xml::read(package, &rel.target).ok()?;
    let list = xml::child(&model, 0, DGM, "ptLst")?;
    let mut order = Vec::new();
    let mut content: BTreeMap<String, String> = BTreeMap::new();
    let mut roots = Vec::new();
    for pt in children(&model, list, DGM, "pt") {
        let node = &model.nodes[pt];
        let Some(id) = node.attr("modelId") else {
            continue;
        };
        match node.attr("type").unwrap_or("node") {
            "doc" => roots.push(id.to_owned()),
            "node" | "asst" => {
                let text = xml::child(&model, pt, DGM, "t")
                    .map_or_else(String::new, |body| paragraphs(&model, body));
                order.push(id.to_owned());
                content.insert(id.to_owned(), text);
            }
            _ => {}
        }
    }
    let mut kids: BTreeMap<String, Vec<(u64, String)>> = BTreeMap::new();
    if let Some(links) = xml::child(&model, 0, DGM, "cxnLst") {
        for cxn in children(&model, links, DGM, "cxn") {
            let node = &model.nodes[cxn];
            if node.attr("type").unwrap_or("parOf") != "parOf" {
                continue;
            }
            let (Some(src), Some(dest)) = (node.attr("srcId"), node.attr("destId")) else {
                continue;
            };
            let ord = node
                .attr("srcOrd")
                .and_then(|ord| ord.trim().parse().ok())
                .unwrap_or(0);
            kids.entry(src.to_owned())
                .or_default()
                .push((ord, dest.to_owned()));
        }
    }
    for list in kids.values_mut() {
        list.sort();
    }
    let mut nodes = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut stack: Vec<(String, u32)> = roots.iter().rev().map(|root| (root.clone(), 0)).collect();
    seen.extend(roots);
    while let Some((id, level)) = stack.pop() {
        let below = match content.get(&id) {
            Some(text) => {
                nodes.push(SmartArtNode {
                    text: text.clone(),
                    level,
                });
                level.saturating_add(1)
            }
            None => level,
        };
        for (_, child) in kids.get(&id).into_iter().flatten().rev() {
            if seen.insert(child.clone()) {
                stack.push((child.clone(), below));
            }
        }
    }
    for id in order {
        if !seen.contains(&id) {
            nodes.push(SmartArtNode {
                text: content.remove(&id).unwrap_or_default(),
                level: 0,
            });
        }
    }
    Some(NodePayload::SmartArt { nodes })
}

/// An OLE frame's program id and the preview picture its fallback shows.
fn ole(package: &Package, part: &str, tree: &XmlTree, frame: usize) -> Option<NodePayload> {
    let objects: Vec<usize> = within(tree, frame)
        .filter(|&at| tree.nodes[at].is(P, "oleObj"))
        .collect();
    if objects.is_empty() {
        return None;
    }
    let prog_id = objects
        .iter()
        .find_map(|&at| tree.nodes[at].attr("progId"))
        .map(str::to_owned);
    let preview = objects.iter().find_map(|&at| {
        let pic = xml::child(tree, at, P, "pic")?;
        picture_media(package, part, tree, pic)
    });
    Some(NodePayload::Ole { prog_id, preview })
}

/// The media a picture element shows: its part and content hash.
pub(crate) fn picture_media(
    package: &Package,
    part: &str,
    tree: &XmlTree,
    picture: usize,
) -> Option<HeldMedia> {
    let blip = xml::path(tree, picture, &[(P, "blipFill"), (A, "blip")])?;
    let embed = tree.nodes[blip].attr_ns(R, "embed")?;
    let rel = package
        .relationships(part)
        .ok()?
        .into_iter()
        .find(|rel| rel.id == embed && !rel.external)?;
    let bytes = package.part(&rel.target).ok()??;
    Some(HeldMedia {
        hash: Digest::of(&bytes),
        part: rel.target,
    })
}
