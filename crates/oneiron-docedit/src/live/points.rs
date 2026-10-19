//! A shape's points (OF-510, Edit Points): the paths of its custom
//! geometry (`a:custGeom`), read and written as PowerPoint's Edit Points
//! draws them.
//!
//! A write replaces only the path list. A preset shape, or one that
//! inherits its geometry, becomes a freeform, as Edit Points converts it.
//! PowerPoint's own connection-site guides (`connsiteX<n>`, `connsiteY<n>`)
//! and the sites that name them are redrawn at the new vertices, and a text
//! rectangle naming a guide the write dropped spans the shape again. The
//! written outline must read back as the live paths.

use super::LiveError;
use super::conversion::Conversion;
use super::convert::element_of;
use super::held::children;
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

/// PowerPoint's connection-site guides and sites at the paths' vertices
/// (each in shape units: a vertex scaled by the shape's extent over its
/// path's size), and how many.
fn sites(a: &str, paths: &[GeomPath]) -> (String, String, u32) {
    let q = |name: &str| xml::qualify(a, name);
    let scale = |coord: &Coord, size: Option<i64>, side: &str| {
        let fmla = match size {
            Some(size) if size > 0 => format!("*/ {} {side} {size}", coord.text()),
            _ => format!("+- {} 0 0", coord.text()),
        };
        xml::escape_attribute(&fmla)
    };
    let (mut guides, mut sites, mut count) = (String::new(), String::new(), 0u32);
    for path in paths {
        for to in path.commands.iter().filter_map(PathCommand::end) {
            guides.push_str(&format!(
                r#"<{gd} name="connsiteX{count}" fmla="{}"/><{gd} name="connsiteY{count}" fmla="{}"/>"#,
                scale(&to.x, path.w, "w"),
                scale(&to.y, path.h, "h"),
                gd = q("gd"),
            ));
            sites.push_str(&format!(
                r#"<{cxn} ang="0"><{pos} x="connsiteX{count}" y="connsiteY{count}"/></{cxn}>"#,
                cxn = q("cxn"),
                pos = q("pos"),
            ));
            count = count.saturating_add(1);
        }
    }
    (guides, sites, count)
}

/// Write `paths` as the outline of the shape `native` on `slide`, as Edit
/// Points does; what it did.
pub(super) fn write(
    package: &mut Package,
    slide: &str,
    native: u32,
    paths: &[GeomPath],
) -> Result<Vec<Conversion>, LiveError> {
    let (bytes, tree) = xml::read(package, slide)?;
    let shape = element_of(&tree, native, "sp").ok_or(LiveError::UnknownNode)?;
    let properties =
        xml::child(&tree, shape, P, "spPr").ok_or(LiveError::Invalid(NO_PROPERTIES))?;
    let mut done = vec![Conversion::PointsEdited {
        paths: u32::try_from(paths.len()).unwrap_or(u32::MAX),
    }];
    let edits = match xml::child(&tree, properties, A, "custGeom") {
        Some(geometry) => redraw(&bytes, &tree, geometry, paths, &mut done),
        None => {
            let (site_guides, site_list, count) = sites("a", paths);
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
/// names a guide no longer defined reset to the shape's bounds.
fn redraw(
    bytes: &[u8],
    tree: &XmlTree,
    geometry: usize,
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
        let (site_guides, site_list, count) = sites(a, paths);
        for &gd in &held_sites {
            edits.push((tree.nodes[gd].span.clone(), Vec::new()));
        }
        edits.push(xml::insert_last(
            bytes,
            &tree.nodes[guide_list],
            &site_guides,
        ));
        match xml::child(tree, geometry, A, "cxnLst") {
            Some(list) => {
                for cxn in children(tree, list, A, "cxn") {
                    let on_site = xml::child(tree, cxn, A, "pos").is_some_and(|pos| {
                        ["x", "y"]
                            .iter()
                            .any(|axis| tree.nodes[pos].attr(axis).is_some_and(site_guide))
                    });
                    if on_site {
                        edits.push((tree.nodes[cxn].span.clone(), Vec::new()));
                    }
                }
                edits.push(xml::insert_last(bytes, &tree.nodes[list], &site_list));
            }
            None => {
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
        defined.retain(|name| !site_guide(name));
        defined
            .extend((0..count).flat_map(|at| [format!("connsiteX{at}"), format!("connsiteY{at}")]));
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
