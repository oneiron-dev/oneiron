//! What a retained element is written as, in live-model terms: a shape's
//! preset or custom geometry, a connector's preset and glue, a table's rows,
//! columns, cells and merges ([`table`]), a chart's plots, categories and
//! series read from its caches, a
//! SmartArt's text outline, an OLE object's program id and preview, and a
//! picture's media identity. The import records it on each node, and the
//! export projector reads it again to write only what the live model changed.

use super::LiveError;
use super::points::{self, GeomPath};
use super::pptx::{ConnectorEnd, HeldMedia, NodeId, NodePayload, SmartArtNode};
use super::svg_fallback;
use crate::deck::{ShapeKind, ShapeView};
use crate::edit::geometry::{glue_of, preset_of};
use crate::edit::xml::{self, A, P, R};
use crate::edit::{ConnectorPreset, Digest, Preset};
use crate::ooxml::XmlTree;
use crate::retained_opc::Package;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const C: &str = "http://schemas.openxmlformats.org/drawingml/2006/chart";
pub(crate) const DGM: &str = "http://schemas.openxmlformats.org/drawingml/2006/diagram";
const OLE: &str = "http://schemas.openxmlformats.org/presentationml/2006/ole";
const FRAME_DATA: &[(&str, &str)] = &[(A, "graphic"), (A, "graphicData")];

mod chart;
pub(super) mod table;

pub(crate) use chart::{bind, chart, chart_part, descriptor, label, plot_family, plots, points};

/// A slide part's parsed tree; [`ShapeView::node`] indexes into it.
pub(crate) fn slide_tree(package: &Package, part: &str) -> Result<XmlTree, LiveError> {
    Ok(xml::read(package, part)?.1)
}

/// A shape's preset, or the shape a picture is cropped to, when it is one
/// the live deck writes. Custom geometry and other presets read as none and
/// stay as written.
pub(crate) fn shape_preset(tree: &XmlTree, shape: &ShapeView) -> Option<Preset> {
    if !matches!(shape.kind, ShapeKind::Shape | ShapeKind::Picture) {
        return None;
    }
    preset_of(tree, shape.node.index).and_then(Preset::from_name)
}

/// A retained element's payload: a shape's custom geometry, a picture's
/// media, a connector's preset and glue (each end through `node_of`, the
/// live node holding a native id on the slide), a chart's data, a
/// SmartArt's text outline, or an OLE object's program id and preview (a
/// table is read with its identities by [`table::import`]). Anything else,
/// and a chart the reader cannot read, reads as none and stays in the
/// retained markup. A chart cache declaring more than the host can hold
/// refuses ([`LiveError::MemoryFloor`]).
pub(crate) fn payload(
    package: &Package,
    part: &str,
    tree: &XmlTree,
    shape: &ShapeView,
    node_of: impl Fn(u32) -> Option<NodeId>,
) -> Result<Option<NodePayload>, LiveError> {
    let at = shape.node.index;
    if matches!(shape.kind, ShapeKind::GraphicFrame)
        && let Some(data) = xml::path(tree, at, FRAME_DATA)
        && tree.nodes[data].attr("uri") == Some(C)
    {
        return match chart_part(package, part, tree, at) {
            Some(target) => chart(package, &target),
            None => Ok(None),
        };
    }
    Ok(other(package, part, tree, shape, node_of))
}

/// [`payload`] for anything but a chart.
fn other(
    package: &Package,
    part: &str,
    tree: &XmlTree,
    shape: &ShapeView,
    node_of: impl Fn(u32) -> Option<NodeId>,
) -> Option<NodePayload> {
    let at = shape.node.index;
    match shape.kind {
        ShapeKind::Shape => Some(NodePayload::CustomGeometry {
            paths: custom_paths(tree, at)?,
        }),
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
            let data = xml::path(tree, at, FRAME_DATA)?;
            match tree.nodes[data].attr("uri")? {
                DGM => smart_art(package, part, tree, data),
                OLE => ole(package, part, tree, at),
                _ => None,
            }
        }
        ShapeKind::Group => None,
    }
}

/// A shape's custom geometry paths, when it is drawn from custom geometry.
pub(crate) fn custom_paths(tree: &XmlTree, shape: usize) -> Option<Vec<GeomPath>> {
    let geometry = xml::path(tree, shape, &[(P, "spPr"), (A, "custGeom")])?;
    Some(points::read(tree, geometry))
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

/// A SmartArt frame's outline from its data part, each node by its model id
/// (see [`smart_art_points`]).
fn smart_art(package: &Package, part: &str, tree: &XmlTree, data: usize) -> Option<NodePayload> {
    let read = smart_art_points(package, part, tree, data)?;
    Some(NodePayload::SmartArt {
        nodes: read.points.into_iter().map(|(_, node)| node).collect(),
    })
}

/// A SmartArt frame's data part and its content points in outline order,
/// each by its model id.
pub(crate) struct SmartArtPoints {
    pub(crate) data: String,
    pub(crate) points: Vec<(String, SmartArtNode)>,
}

/// The SmartArt in the graphic frame `frame` of slide `part`.
pub(crate) fn smart_art_of(
    package: &Package,
    part: &str,
    tree: &XmlTree,
    frame: usize,
) -> Option<SmartArtPoints> {
    let data = xml::path(tree, frame, FRAME_DATA)?;
    if tree.nodes[data].attr("uri")? != DGM {
        return None;
    }
    smart_art_points(package, part, tree, data)
}

/// A SmartArt's content points from its data part: each point (a node or
/// an assistant) in the order its parent lists it, at its depth below the
/// document point. A point no parent lists follows at level 0.
fn smart_art_points(
    package: &Package,
    part: &str,
    tree: &XmlTree,
    data: usize,
) -> Option<SmartArtPoints> {
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
                nodes.push((
                    id.clone(),
                    SmartArtNode {
                        text: text.clone(),
                        level,
                        id: Some(id.clone()),
                    },
                ));
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
            let text = content.remove(&id).unwrap_or_default();
            nodes.push((
                id.clone(),
                SmartArtNode {
                    text,
                    level: 0,
                    id: Some(id),
                },
            ));
        }
    }
    Some(SmartArtPoints {
        data: rel.target,
        points: nodes,
    })
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

/// The media a picture element shows: its part and content hash. Office's
/// SVG picture shows the SVG its blip's `asvg:svgBlip` extension names, over
/// the raster the blip embeds as its fallback (FIX 5727); a blip with no
/// such extension, or one naming no part the package holds, shows what it
/// embeds.
pub(crate) fn picture_media(
    package: &Package,
    part: &str,
    tree: &XmlTree,
    picture: usize,
) -> Option<HeldMedia> {
    let blip = xml::path(tree, picture, &[(P, "blipFill"), (A, "blip")])?;
    let rels = package.relationships(part).ok()?;
    let media = |at: usize| {
        let embed = tree.nodes[at].attr_ns(R, "embed")?;
        let rel = rels.iter().find(|rel| rel.id == embed && !rel.external)?;
        let bytes = package.part(&rel.target).ok()??;
        Some(HeldMedia {
            hash: Digest::of(&bytes),
            part: rel.target.clone(),
        })
    };
    svg_fallback::svg_blip(tree, blip)
        .and_then(&media)
        .or_else(|| media(blip))
}
