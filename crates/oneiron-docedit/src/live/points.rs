//! A shape's points (OF-510, Edit Points): the paths of its custom
//! geometry (`a:custGeom`), read and written as PowerPoint's Edit Points
//! draws them.
//!
//! A write replaces only the path list. A preset shape, or one that
//! inherits its geometry, becomes a freeform, as Edit Points converts it.
//! PowerPoint's own connection-site guides (`connsiteX<n>`, `connsiteY<n>`)
//! and the sites that name them are redrawn at the new vertices, and a text
//! rectangle naming a guide the write dropped spans the shape again. A site
//! a glued connector names keeps its index, position and guides (FIX 5671),
//! so no glued end names a site the shape no longer has. The written
//! outline must read back as the live paths.

use super::LiveError;
use super::conversion::Conversion;
use super::convert::element_of;
use super::held::{children, within};
use super::pptx::{LiveDeck, NodeId, NodePayload};
use crate::edit::xml::{self, A, P};
use crate::ooxml::XmlTree;
use crate::retained_opc::Package;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The guides every shape defines (ECMA-376 Part 1, 20.1.10.56).
const BUILT_IN: &[&str] = &[
    "3cd4", "3cd8", "5cd8", "7cd8", "b", "cd2", "cd4", "cd8", "h", "hc", "hd2", "hd3", "hd4",
    "hd5", "hd6", "hd8", "l", "ls", "r", "ss", "ssd16", "ssd2", "ssd32", "ssd4", "ssd6", "ssd8",
    "t", "vc", "w", "wd10", "wd12", "wd2", "wd3", "wd32", "wd4", "wd5", "wd6", "wd8",
];
/// A path may name only a guide its shape defines.
const UNKNOWN_GUIDE: &str = "a path names a guide the shape does not define (only the built-in guides and those its paths read with)";
const NEGATIVE_SIZE: &str = "a path's width and height are not negative";
const NO_PROPERTIES: &str = "the shape has no shape properties to draw its points in";
const READ_BACK: &str = "written points do not read back as the live paths";

/// One path of a shape's custom geometry (`a:path`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GeomPath {
    /// The path's own coordinate space; none is the shape's extent in EMU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub w: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h: Option<i64>,
    /// How the path fills; none is a normal fill.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fill: Option<PathFill>,
    /// Whether the path is outlined; none is outlined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stroke: Option<bool>,
    /// Whether a 3D extrusion may use the path; none is yes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extrusion_ok: Option<bool>,
    pub commands: Vec<PathCommand>,
}

/// How a path fills (`a:path/@fill`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PathFill {
    /// No fill: an open outline.
    #[serde(rename = "none")]
    Unfilled,
    Norm,
    Lighten,
    LightenLess,
    Darken,
    DarkenLess,
}

impl PathFill {
    const ALL: [Self; 6] = [
        Self::Unfilled,
        Self::Norm,
        Self::Lighten,
        Self::LightenLess,
        Self::Darken,
        Self::DarkenLess,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Unfilled => "none",
            Self::Norm => "norm",
            Self::Lighten => "lighten",
            Self::LightenLess => "lightenLess",
            Self::Darken => "darken",
            Self::DarkenLess => "darkenLess",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|fill| fill.name() == name)
    }
}

/// One drawing command of a path, in path units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PathCommand {
    /// Start a figure at this point.
    MoveTo {
        to: PathPoint,
    },
    LineTo {
        to: PathPoint,
    },
    /// An arc from the current point: its ellipse's radii, and its start
    /// and swing angles in 60,000ths of a degree.
    ArcTo {
        w_r: Coord,
        h_r: Coord,
        st_ang: Coord,
        sw_ang: Coord,
    },
    QuadBezTo {
        control: PathPoint,
        to: PathPoint,
    },
    CubicBezTo {
        control1: PathPoint,
        control2: PathPoint,
        to: PathPoint,
    },
    /// Close the figure back to its start.
    Close,
}

/// A point of a path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PathPoint {
    pub x: Coord,
    pub y: Coord,
}

/// A coordinate: a number of path units, or the name of a shape guide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum Coord {
    Value(i64),
    Guide(String),
}

impl Coord {
    fn read(value: Option<&str>) -> Self {
        match value {
            Some(text) => text
                .trim()
                .parse()
                .map_or_else(|_| Self::Guide(text.to_owned()), Self::Value),
            None => Self::Value(0),
        }
    }

    fn text(&self) -> String {
        match self {
            Self::Value(value) => value.to_string(),
            Self::Guide(name) => name.clone(),
        }
    }
}

impl PathCommand {
    fn coords(&self) -> Vec<&Coord> {
        match self {
            Self::MoveTo { to } | Self::LineTo { to } => vec![&to.x, &to.y],
            Self::ArcTo {
                w_r,
                h_r,
                st_ang,
                sw_ang,
            } => vec![w_r, h_r, st_ang, sw_ang],
            Self::QuadBezTo { control, to } => vec![&control.x, &control.y, &to.x, &to.y],
            Self::CubicBezTo {
                control1,
                control2,
                to,
            } => vec![
                &control1.x,
                &control1.y,
                &control2.x,
                &control2.y,
                &to.x,
                &to.y,
            ],
            Self::Close => Vec::new(),
        }
    }

    /// The vertex the command ends at; an arc's is computed, not written.
    fn end(&self) -> Option<&PathPoint> {
        match self {
            Self::MoveTo { to }
            | Self::LineTo { to }
            | Self::QuadBezTo { to, .. }
            | Self::CubicBezTo { to, .. } => Some(to),
            Self::ArcTo { .. } | Self::Close => None,
        }
    }
}

/// Every guide name the paths use.
fn guides(paths: &[GeomPath]) -> BTreeSet<&str> {
    paths
        .iter()
        .flat_map(|path| &path.commands)
        .flat_map(PathCommand::coords)
        .filter_map(|coord| match coord {
            Coord::Guide(name) => Some(name.as_str()),
            Coord::Value(_) => None,
        })
        .collect()
}

/// A guide PowerPoint writes for a freeform's connection site.
fn site_guide(name: &str) -> bool {
    ["connsiteX", "connsiteY"].iter().any(|stem| {
        name.strip_prefix(stem)
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// Paths written over a shape whose paths were `held` (none for a preset or
/// live-born shape): sizes are not negative, and every guide they name is a
/// built-in one or one the held paths name.
pub(super) fn check(paths: &[GeomPath], held: &[GeomPath]) -> Result<(), LiveError> {
    if paths
        .iter()
        .any(|path| path.w.is_some_and(|w| w < 0) || path.h.is_some_and(|h| h < 0))
    {
        return Err(LiveError::Invalid(NEGATIVE_SIZE));
    }
    let known = guides(held);
    if guides(paths)
        .iter()
        .all(|name| known.contains(name) || BUILT_IN.contains(name))
    {
        Ok(())
    } else {
        Err(LiveError::Invalid(UNKNOWN_GUIDE))
    }
}

/// The paths of the custom geometry at `geometry` (`a:custGeom`).
pub(crate) fn read(tree: &XmlTree, geometry: usize) -> Vec<GeomPath> {
    let Some(list) = xml::child(tree, geometry, A, "pathLst") else {
        return Vec::new();
    };
    let point = |at: usize| PathPoint {
        x: Coord::read(tree.nodes[at].attr("x")),
        y: Coord::read(tree.nodes[at].attr("y")),
    };
    children(tree, list, A, "path")
        .map(|path| {
            let node = &tree.nodes[path];
            let int = |name: &str| node.attr(name).and_then(|value| value.trim().parse().ok());
            let flag = |name: &str| {
                node.attr(name)
                    .map(|value| matches!(value.trim(), "1" | "true"))
            };
            let commands = node
                .children
                .iter()
                .copied()
                .filter(|&at| tree.nodes[at].namespace == A)
                .filter_map(|at| {
                    let command = &tree.nodes[at];
                    let mut points = children(tree, at, A, "pt").map(point);
                    let arc = |name: &str| Coord::read(command.attr(name));
                    Some(match command.name.as_str() {
                        "moveTo" => PathCommand::MoveTo { to: points.next()? },
                        "lnTo" => PathCommand::LineTo { to: points.next()? },
                        "arcTo" => PathCommand::ArcTo {
                            w_r: arc("wR"),
                            h_r: arc("hR"),
                            st_ang: arc("stAng"),
                            sw_ang: arc("swAng"),
                        },
                        "quadBezTo" => PathCommand::QuadBezTo {
                            control: points.next()?,
                            to: points.next()?,
                        },
                        "cubicBezTo" => PathCommand::CubicBezTo {
                            control1: points.next()?,
                            control2: points.next()?,
                            to: points.next()?,
                        },
                        "close" => PathCommand::Close,
                        _ => return None,
                    })
                })
                .collect();
            GeomPath {
                w: int("w"),
                h: int("h"),
                fill: node.attr("fill").and_then(PathFill::from_name),
                stroke: flag("stroke"),
                extrusion_ok: flag("extrusionOk"),
                commands,
            }
        })
        .collect()
}

/// `a:pathLst` holding `paths`, under the DrawingML prefix `a`.
fn path_list(a: &str, paths: &[GeomPath]) -> String {
    let q = |name: &str| xml::qualify(a, name);
    let coord = |coord: &Coord| xml::escape_attribute(&coord.text());
    let pt = |point: &PathPoint| {
        format!(
            r#"<{} x="{}" y="{}"/>"#,
            q("pt"),
            coord(&point.x),
            coord(&point.y)
        )
    };
    let mut out = format!("<{}>", q("pathLst"));
    for path in paths {
        let mut open = q("path");
        if let Some(w) = path.w {
            open.push_str(&format!(r#" w="{w}""#));
        }
        if let Some(h) = path.h {
            open.push_str(&format!(r#" h="{h}""#));
        }
        if let Some(fill) = path.fill {
            open.push_str(&format!(r#" fill="{}""#, fill.name()));
        }
        for (name, value) in [("stroke", path.stroke), ("extrusionOk", path.extrusion_ok)] {
            if let Some(value) = value {
                open.push_str(&format!(r#" {name}="{}""#, u8::from(value)));
            }
        }
        out.push_str(&format!("<{open}>"));
        for command in &path.commands {
            let wrap = |name: &str, points: &[&PathPoint]| {
                let inner: String = points.iter().map(|&point| pt(point)).collect();
                format!("<{tag}>{inner}</{tag}>", tag = q(name))
            };
            out.push_str(&match command {
                PathCommand::MoveTo { to } => wrap("moveTo", &[to]),
                PathCommand::LineTo { to } => wrap("lnTo", &[to]),
                PathCommand::ArcTo {
                    w_r,
                    h_r,
                    st_ang,
                    sw_ang,
                } => format!(
                    r#"<{} wR="{}" hR="{}" stAng="{}" swAng="{}"/>"#,
                    q("arcTo"),
                    coord(w_r),
                    coord(h_r),
                    coord(st_ang),
                    coord(sw_ang)
                ),
                PathCommand::QuadBezTo { control, to } => wrap("quadBezTo", &[control, to]),
                PathCommand::CubicBezTo {
                    control1,
                    control2,
                    to,
                } => wrap("cubicBezTo", &[control1, control2, to]),
                PathCommand::Close => format!("<{}/>", q("close")),
            });
        }
        out.push_str(&format!("</{}>", q("path")));
    }
    out.push_str(&format!("</{}>", q("pathLst")));
    out
}

/// One connection site drawn at a vertex: its two guides and its `a:cxn`.
struct Site {
    guides: String,
    cxn: String,
    /// The number its guides are named by.
    number: u32,
}

/// PowerPoint's connection-site guides and sites at the paths' vertices
/// (each in shape units: a vertex scaled by the shape's extent over its
/// path's size), one per vertex, their guides numbered past any name in
/// `taken`.
fn sites(a: &str, paths: &[GeomPath], taken: &BTreeSet<String>) -> Vec<Site> {
    let q = |name: &str| xml::qualify(a, name);
    let scale = |coord: &Coord, size: Option<i64>, side: &str| {
        let fmla = match size {
            Some(size) if size > 0 => format!("*/ {} {side} {size}", coord.text()),
            _ => format!("+- {} 0 0", coord.text()),
        };
        xml::escape_attribute(&fmla)
    };
    let free = |n: u32| {
        !taken.contains(&format!("connsiteX{n}")) && !taken.contains(&format!("connsiteY{n}"))
    };
    let (mut out, mut number) = (Vec::new(), 0u32);
    for path in paths {
        for to in path.commands.iter().filter_map(PathCommand::end) {
            while !free(number) {
                number = number.saturating_add(1);
            }
            out.push(Site {
                guides: format!(
                    r#"<{gd} name="connsiteX{number}" fmla="{}"/><{gd} name="connsiteY{number}" fmla="{}"/>"#,
                    scale(&to.x, path.w, "w"),
                    scale(&to.y, path.h, "h"),
                    gd = q("gd"),
                ),
                cxn: format!(
                    r#"<{cxn} ang="0"><{pos} x="connsiteX{number}" y="connsiteY{number}"/></{cxn}>"#,
                    cxn = q("cxn"),
                    pos = q("pos"),
                ),
                number,
            });
            number = number.saturating_add(1);
        }
    }
    out
}

/// The connection sites of the node `node` that the live deck's connectors
/// glue to.
pub(super) fn glued_sites(deck: &LiveDeck, node: NodeId) -> BTreeSet<u32> {
    deck.nodes
        .values()
        .filter_map(|held| match &held.payload {
            Some(NodePayload::Connector { start, end, .. }) => Some([*start, *end]),
            _ => None,
        })
        .flatten()
        .flatten()
        .filter(|end| end.node == node)
        .map(|end| end.site)
        .collect()
}

/// The connection sites of the shape `native` that the slide's connectors
/// are glued to (`a:stCxn`, `a:endCxn`).
fn slide_glue(tree: &XmlTree, native: u32) -> impl Iterator<Item = u32> + '_ {
    within(tree, 0)
        .filter(move |&at| tree.nodes[at].is(A, "stCxn") || tree.nodes[at].is(A, "endCxn"))
        .filter(move |&at| {
            tree.nodes[at]
                .attr("id")
                .and_then(|id| id.trim().parse::<u32>().ok())
                == Some(native)
        })
        .filter_map(move |at| tree.nodes[at].attr("idx")?.trim().parse().ok())
}

/// Write `paths` as the outline of the shape `native` on `slide`, as Edit
/// Points does; what it did. `glued` names the sites the live deck's
/// connectors glue to; with those the slide's connectors are glued to, they
/// are kept as they are.
pub(super) fn write(
    package: &mut Package,
    slide: &str,
    native: u32,
    paths: &[GeomPath],
    glued: &BTreeSet<u32>,
) -> Result<Vec<Conversion>, LiveError> {
    let (bytes, tree) = xml::read(package, slide)?;
    let shape = element_of(&tree, native, "sp").ok_or(LiveError::UnknownNode)?;
    let properties =
        xml::child(&tree, shape, P, "spPr").ok_or(LiveError::Invalid(NO_PROPERTIES))?;
    let mut done = vec![Conversion::PointsEdited {
        paths: u32::try_from(paths.len()).unwrap_or(u32::MAX),
    }];
    let edits = match xml::child(&tree, properties, A, "custGeom") {
        Some(geometry) => {
            let mut glued = glued.clone();
            glued.extend(slide_glue(&tree, native));
            redraw(&bytes, &tree, (geometry, &glued), paths, &mut done)
        }
        None => {
            let drawn = sites("a", paths, &BTreeSet::new());
            let count = u32::try_from(drawn.len()).unwrap_or(u32::MAX);
            let site_guides: String = drawn.iter().map(|site| site.guides.as_str()).collect();
            let site_list: String = drawn.iter().map(|site| site.cxn.as_str()).collect();
            let geometry = format!(
                r#"<a:custGeom xmlns:a="{A}"><a:avLst/><a:gdLst>{site_guides}</a:gdLst><a:ahLst/><a:cxnLst>{site_list}</a:cxnLst><a:rect l="l" t="t" r="r" b="b"/>{}</a:custGeom>"#,
                path_list("a", paths)
            );
            if count > 0 {
                done.push(Conversion::VertexSitesRedrawn { sites: count });
            }
            // CT_ShapeProperties: xfrm?, then the geometry.
            vec![match xml::child(&tree, properties, A, "prstGeom") {
                Some(preset) => (tree.nodes[preset].span.clone(), geometry.into_bytes()),
                None => match xml::child(&tree, properties, A, "xfrm") {
                    Some(xfrm) => {
                        let at = tree.nodes[xfrm].span.end;
                        (at..at, geometry.into_bytes())
                    }
                    None => xml::insert_first(&bytes, &tree.nodes[properties], &geometry),
                },
            }]
        }
    };
    package.replace_xml_part(slide, xml::splice(&bytes, edits)?)?;
    let (_, after) = xml::read(package, slide)?;
    let back = element_of(&after, native, "sp")
        .and_then(|shape| xml::path(&after, shape, &[(P, "spPr"), (A, "custGeom")]))
        .map(|geometry| read(&after, geometry));
    if back.as_deref() != Some(paths) {
        return Err(LiveError::Invalid(READ_BACK));
    }
    Ok(done)
}

/// The edits that draw `paths` over a shape's own custom geometry: its path
/// list replaced, PowerPoint's connection-site guides and sites redrawn at
/// the new vertices (unless a path names one), and a text rectangle that
/// names a guide no longer defined reset to the shape's bounds. A site at an
/// index in `glued`, and a site that is no vertex site, keeps its index,
/// bytes and guides; the vertex sites take the other indices in order, then
/// follow the list.
fn redraw(
    bytes: &[u8],
    tree: &XmlTree,
    (geometry, glued): (usize, &BTreeSet<u32>),
    paths: &[GeomPath],
    done: &mut Vec<Conversion>,
) -> Vec<xml::Splice> {
    let a = xml::prefix(&tree.nodes[geometry]);
    let q = |name: &str| xml::qualify(a, name);
    let list = path_list(a, paths);
    let mut edits = vec![match xml::child(tree, geometry, A, "pathLst") {
        Some(at) => (tree.nodes[at].span.clone(), list.into_bytes()),
        None => xml::insert_last(bytes, &tree.nodes[geometry], &list),
    }];
    let named = |at: usize, attribute: &str| tree.nodes[at].attr(attribute).map(str::to_owned);
    let guide_list = xml::child(tree, geometry, A, "gdLst");
    let mut defined: BTreeSet<String> = ["avLst", "gdLst"]
        .iter()
        .filter_map(|list| xml::child(tree, geometry, A, list))
        .flat_map(|list| children(tree, list, A, "gd"))
        .filter_map(|gd| named(gd, "name"))
        .collect();
    let held_sites: Vec<usize> = guide_list
        .map(|list| {
            children(tree, list, A, "gd")
                .filter(|&gd| tree.nodes[gd].attr("name").is_some_and(site_guide))
                .collect()
        })
        .unwrap_or_default();
    if let Some(guide_list) = guide_list
        && !held_sites.is_empty()
        && !guides(paths).into_iter().any(site_guide)
    {
        let cxns: Vec<usize> = xml::child(tree, geometry, A, "cxnLst")
            .map(|list| children(tree, list, A, "cxn").collect())
            .unwrap_or_default();
        let slots = kept_slots(tree, &cxns, glued, paths);
        // The site guides a kept site names, and those their formulas name.
        let mut kept: BTreeSet<String> = cxns
            .iter()
            .zip(&slots)
            .filter(|&(_, &slot)| slot == Slot::Kept)
            .filter_map(|(&cxn, _)| xml::child(tree, cxn, A, "pos"))
            .flat_map(|pos| ["x", "y"].map(|axis| named(pos, axis)))
            .flatten()
            .filter(|name| site_guide(name))
            .collect();
        for &gd in held_sites.iter().rev() {
            if named(gd, "name").is_some_and(|name| kept.contains(&name)) {
                let fmla = tree.nodes[gd].attr("fmla").unwrap_or_default();
                kept.extend(
                    fmla.split_whitespace()
                        .filter(|token| site_guide(token))
                        .map(str::to_owned),
                );
            }
        }
        let drawn = sites(a, paths, &kept);
        let count = u32::try_from(drawn.len()).unwrap_or(u32::MAX);
        for &gd in &held_sites {
            if !named(gd, "name").is_some_and(|name| kept.contains(&name)) {
                edits.push((tree.nodes[gd].span.clone(), Vec::new()));
            }
        }
        let site_guides: String = drawn.iter().map(|site| site.guides.as_str()).collect();
        edits.push(xml::insert_last(
            bytes,
            &tree.nodes[guide_list],
            &site_guides,
        ));
        let numbers: Vec<u32> = drawn.iter().map(|site| site.number).collect();
        let mut fresh = drawn.into_iter().map(|site| site.cxn);
        match xml::child(tree, geometry, A, "cxnLst") {
            Some(list) => {
                for (&cxn, slot) in cxns.iter().zip(&slots) {
                    match slot {
                        Slot::Kept => {}
                        Slot::Redrawn => {
                            let site = fresh.next().unwrap_or_default();
                            edits.push((tree.nodes[cxn].span.clone(), site.into_bytes()));
                        }
                        Slot::Dropped => edits.push((tree.nodes[cxn].span.clone(), Vec::new())),
                    }
                }
                let rest: String = fresh.collect();
                edits.push(xml::insert_last(bytes, &tree.nodes[list], &rest));
            }
            None => {
                let site_list: String = fresh.collect();
                // CT_CustomGeometry2D: avLst?, gdLst?, ahLst?, cxnLst?, rect?, pathLst.
                let element = format!("<{list}>{site_list}</{list}>", list = q("cxnLst"));
                let before = xml::child(tree, geometry, A, "rect")
                    .or_else(|| xml::child(tree, geometry, A, "pathLst"));
                edits.push(match before {
                    Some(at) => {
                        let start = tree.nodes[at].span.start;
                        (start..start, element.into_bytes())
                    }
                    None => xml::insert_last(bytes, &tree.nodes[geometry], &element),
                });
            }
        }
        defined.retain(|name| !site_guide(name) || kept.contains(name));
        defined.extend(
            numbers
                .iter()
                .flat_map(|n| [format!("connsiteX{n}"), format!("connsiteY{n}")]),
        );
        done.push(Conversion::VertexSitesRedrawn { sites: count });
    }
    if let Some(rect) = xml::child(tree, geometry, A, "rect") {
        let dropped = ["l", "t", "r", "b"].iter().any(|side| {
            tree.nodes[rect].attr(side).is_some_and(|name| {
                name.trim().parse::<i64>().is_err()
                    && !BUILT_IN.contains(&name)
                    && !defined.contains(name)
            })
        });
        if dropped {
            edits.push((
                tree.nodes[rect].span.clone(),
                format!(r#"<{} l="l" t="t" r="r" b="b"/>"#, q("rect")).into_bytes(),
            ));
            done.push(Conversion::TextRectReset);
        }
    }
    edits
}

/// What a redraw does with a held connection site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    /// Kept as it is: glued, no vertex site, or holding the index of a kept
    /// site after it once the vertex sites ran out.
    Kept,
    /// The next vertex site takes its index.
    Redrawn,
    /// Removed: a vertex site past the vertices and every kept site.
    Dropped,
}

/// What the redraw of `paths` does with each held site `cxns`: a site a
/// glued connector names (`glued`), or one not on PowerPoint's site guides,
/// is kept at its index; each other site takes the next new vertex site;
/// once those run out, a site before a kept one is kept to hold its index,
/// and the rest are dropped.
fn kept_slots(
    tree: &XmlTree,
    cxns: &[usize],
    glued: &BTreeSet<u32>,
    paths: &[GeomPath],
) -> Vec<Slot> {
    let on_site = |cxn: usize| {
        xml::child(tree, cxn, A, "pos").is_some_and(|pos| {
            ["x", "y"]
                .iter()
                .any(|axis| tree.nodes[pos].attr(axis).is_some_and(site_guide))
        })
    };
    let held: Vec<bool> = cxns
        .iter()
        .enumerate()
        .map(|(index, &cxn)| {
            !on_site(cxn) || u32::try_from(index).is_ok_and(|index| glued.contains(&index))
        })
        .collect();
    let last_held = held.iter().rposition(|&held| held);
    let mut vertices = paths
        .iter()
        .flat_map(|path| &path.commands)
        .filter_map(PathCommand::end)
        .count();
    held.iter()
        .enumerate()
        .map(|(index, &held)| {
            if held {
                Slot::Kept
            } else if vertices > 0 {
                vertices -= 1;
                Slot::Redrawn
            } else if last_held.is_some_and(|last| last > index) {
                Slot::Kept
            } else {
                Slot::Dropped
            }
        })
        .collect()
}
