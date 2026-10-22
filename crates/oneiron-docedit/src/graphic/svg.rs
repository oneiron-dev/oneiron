//! The closed SVG subset compiled to native shapes. Coordinates stay absolute
//! in the viewBox at 1px = 9,525 EMU; the group's transform places the
//! viewBox in the slide. Refused classes are found over the whole document
//! before any geometry is read, so a gradient in `defs` is named as a
//! gradient, not as an unsupported `defs`. Node, depth and segment counts
//! are observations (FIX 8574): the tree and each shape's geometry reserve
//! their memory through the operation's port, and groups nest on a heap
//! stack, not the call stack.

use super::geometry::{self, Linear, MAX_PX, emu};
use super::path::{self, Affine};
use super::{
    Cap, Drawing, Extent, Frame, Geometry, GraphicError, Join, NativeShape, Preset, Refused, Solid,
    Stroke, fit,
};
use crate::design_plan::Rect;
use crate::ooxml::{Node, XmlError, XmlTree};
use crate::resource::{Resources, bytes_of};

const SVG_NS: &str = "http://www.w3.org/2000/svg";
/// ST_LineWidth's ceiling, in EMU.
const MAX_LINE: i64 = 20_116_800;
const MAX_MITER: f64 = 1_000.0;
/// Rounding slack for the viewBox check, in EMU.
const SLACK: f64 = 1.0;
/// Presentation attributes every drawing element and group takes.
const PAINT: &[&str] = &[
    "id",
    "fill",
    "fill-opacity",
    "fill-rule",
    "stroke",
    "stroke-width",
    "stroke-opacity",
    "stroke-linecap",
    "stroke-linejoin",
    "stroke-miterlimit",
    "opacity",
];

pub(super) fn compile(
    bytes: &[u8],
    bounds: Rect,
    resources: &Resources,
) -> Result<Drawing, GraphicError> {
    instructions(bytes)?;
    let tree = XmlTree::parse(bytes, resources).map_err(|error| match error {
        XmlError::Resource(refusal) => GraphicError::Resource(refusal),
        XmlError::Invalid(reason) => GraphicError::Svg {
            at: 0,
            element: String::new(),
            refused: Refused::Malformed(reason),
        },
    })?;
    for (at, node) in tree.nodes.iter().enumerate() {
        refused_class(at, node)?;
    }
    for (at, node) in tree.nodes.iter().enumerate() {
        refused_attributes(at, node)?;
    }
    let view = document(&tree)?;
    let mut compiler = Compiler {
        tree: &tree,
        resources,
        view,
        shapes: Vec::new(),
    };
    let style = Style::default().inherit(0, &tree.nodes[0])?;
    compiler.children(0, &style, Affine::IDENTITY)?;
    let extent = Extent {
        cx: view.cx,
        cy: view.cy,
    };
    Ok(Drawing {
        child: view,
        placed: fit(extent, bounds),
        shapes: compiler.shapes,
    })
}

fn refuse(at: usize, node: &Node, refused: Refused) -> GraphicError {
    if let Refused::Resource(refusal) = refused {
        return GraphicError::Resource(refusal);
    }
    GraphicError::Svg {
        at,
        element: node.name.clone(),
        refused,
    }
}

/// Processing instructions never reach the node arena, so a style-sheet link
/// would pass unseen: refuse every one but the XML declaration.
fn instructions(bytes: &[u8]) -> Result<(), GraphicError> {
    for (at, window) in bytes.windows(2).enumerate() {
        if window == b"<?" && !(at == 0 && bytes.starts_with(b"<?xml ")) {
            let refused = if bytes[at..].starts_with(b"<?xml-stylesheet") {
                Refused::Css
            } else {
                Refused::Malformed("processing instruction")
            };
            return Err(GraphicError::Svg {
                at: 0,
                element: String::new(),
                refused,
            });
        }
    }
    Ok(())
}

fn refused_class(at: usize, node: &Node) -> Result<(), GraphicError> {
    let refused = match node.name.as_str() {
        "script" | "animate" | "animateMotion" | "animateTransform" | "animateColor" | "set"
        | "discard" => Refused::Active,
        "foreignObject" => Refused::ForeignObject,
        "style" => Refused::Css,
        "mask" => Refused::Mask,
        "pattern" => Refused::Pattern,
        "clipPath" => Refused::ClipPath,
        "linearGradient" | "radialGradient" | "meshgradient" => Refused::Gradient,
        "textPath" => Refused::TextOnPath,
        "text" | "tspan" => Refused::Text,
        name if name == "filter" || name.starts_with("fe") => Refused::Filter,
        _ => return Ok(()),
    };
    Err(refuse(at, node, refused))
}

fn refused_attributes(at: usize, node: &Node) -> Result<(), GraphicError> {
    for (name, value) in &node.attrs {
        let local = name.rsplit(':').next().unwrap_or(name);
        let refused = if local == "href" {
            // A local `#id` reaches only elements outside the subset.
            if value.trim_start().starts_with('#') {
                continue;
            }
            Refused::ExternalReference
        } else if name.contains(':') {
            continue;
        } else {
            match name.as_str() {
                event if event.starts_with("on") => Refused::Active,
                "style" | "class" => Refused::Css,
                "filter" => Refused::Filter,
                "mask" => Refused::Mask,
                "clip-path" | "clip" => Refused::ClipPath,
                _ => match url(value) {
                    Some(true) => Refused::Value(name.clone()),
                    Some(false) => Refused::ExternalReference,
                    None => continue,
                },
            }
        };
        return Err(refuse(at, node, refused));
    }
    Ok(())
}

/// Whether `value` holds a `url(...)`, and if so whether it is a local `#id`.
fn url(value: &str) -> Option<bool> {
    let (_, target) = value.split_once("url(")?;
    Some(
        target
            .trim_start()
            .trim_start_matches(['"', '\''])
            .starts_with('#'),
    )
}

/// Every attribute must be a namespace declaration, a presentation attribute
/// (when `paint`), or one of `own`.
fn allowed(at: usize, node: &Node, own: &[&str], paint: bool) -> Result<(), GraphicError> {
    for name in node.attrs.keys() {
        let name = name.as_str();
        if name == "xmlns"
            || name.starts_with("xmlns:")
            || own.contains(&name)
            || (paint && PAINT.contains(&name))
        {
            continue;
        }
        return Err(refuse(at, node, Refused::Attribute(name.to_owned())));
    }
    Ok(())
}

/// The root's viewBox in EMU, which must equal its explicit size.
fn document(tree: &XmlTree) -> Result<Rect, GraphicError> {
    let root = &tree.nodes[0];
    let bad = || refuse(0, root, Refused::Document);
    if !root.is(SVG_NS, "svg") {
        return Err(bad());
    }
    allowed(0, root, &["width", "height", "viewBox", "version"], true)?;
    let view = root.attr("viewBox").and_then(path::numbers);
    let width = root.attr("width").and_then(length);
    let height = root.attr("height").and_then(length);
    let (Some(&[x, y, w, h]), Some(width), Some(height)) = (view.as_deref(), width, height) else {
        return Err(bad());
    };
    let inside = |v: f64| v.abs() <= MAX_PX;
    if !(w > 0.0 && h > 0.0 && inside(x) && inside(y) && inside(w) && inside(h))
        || width != w
        || height != h
    {
        return Err(bad());
    }
    let (left, top) = (emu(x).map_err(|_| bad())?, emu(y).map_err(|_| bad())?);
    let right = emu(x + w).map_err(|_| bad())?;
    let bottom = emu(y + h).map_err(|_| bad())?;
    if right <= left || bottom <= top {
        return Err(bad());
    }
    Ok(Rect {
        x: left,
        y: top,
        cx: right - left,
        cy: bottom - top,
    })
}

/// A root length: unitless or px.
fn length(value: &str) -> Option<f64> {
    let value = value.trim();
    path::number(value.strip_suffix("px").unwrap_or(value))
}

#[derive(Debug, Clone, Copy)]
struct Style {
    fill: Option<[u8; 3]>,
    fill_alpha: f64,
    stroke: Option<[u8; 3]>,
    width: f64,
    stroke_alpha: f64,
    cap: Cap,
    join: Join,
    miter: f64,
}

impl Default for Style {
    /// SVG's initial values: black fill, no stroke, width 1, butt caps,
    /// miter joins at limit 4.
    fn default() -> Self {
        Self {
            fill: Some([0, 0, 0]),
            fill_alpha: 1.0,
            stroke: None,
            width: 1.0,
            stroke_alpha: 1.0,
            cap: Cap::Flat,
            join: Join::Miter { limit: 0 },
            miter: 4.0,
        }
    }
}

impl Style {
    fn inherit(&self, at: usize, node: &Node) -> Result<Self, GraphicError> {
        let mut style = *self;
        for (name, value) in &node.attrs {
            let value = value.trim();
            let parsed = match name.as_str() {
                "fill" => paint(value).map(|fill| style.fill = fill),
                "stroke" => paint(value).map(|stroke| style.stroke = stroke),
                "fill-opacity" => unit(value).map(|alpha| style.fill_alpha = alpha),
                "stroke-opacity" => unit(value).map(|alpha| style.stroke_alpha = alpha),
                "stroke-width" => path::number(value)
                    .filter(|width| *width >= 0.0)
                    .map(|width| style.width = width),
                "stroke-linecap" => match value {
                    "butt" => Some(Cap::Flat),
                    "round" => Some(Cap::Round),
                    "square" => Some(Cap::Square),
                    _ => None,
                }
                .map(|cap| style.cap = cap),
                "stroke-linejoin" => match value {
                    "miter" => Some(Join::Miter { limit: 0 }),
                    "round" => Some(Join::Round),
                    "bevel" => Some(Join::Bevel),
                    _ => None,
                }
                .map(|join| style.join = join),
                "stroke-miterlimit" => path::number(value)
                    .filter(|limit| (1.0..=MAX_MITER).contains(limit))
                    .map(|limit| style.miter = limit),
                // Settled per shape: only outlines both rules paint alike pass.
                "fill-rule" => matches!(value, "nonzero" | "evenodd").then_some(()),
                // Group opacity composites; alpha is per paint.
                "opacity" => (path::number(value) == Some(1.0)).then_some(()),
                _ => Some(()),
            };
            if parsed.is_none() {
                return Err(refuse(at, node, Refused::Value(name.clone())));
            }
        }
        Ok(style)
    }

    fn fill(&self) -> Option<Solid> {
        self.fill.map(|rgb| Solid {
            rgb,
            alpha: alpha(self.fill_alpha),
        })
    }

    fn stroke(&self, linear: Linear) -> Result<Option<Stroke>, Refused> {
        let Some(rgb) = self.stroke else {
            return Ok(None);
        };
        if self.width == 0.0 {
            return Ok(None);
        }
        if linear.sx != linear.sy {
            return Err(Refused::StrokeTransform);
        }
        let width = emu(self.width * linear.sx)?;
        if !(1..=MAX_LINE).contains(&width) {
            return Err(Refused::Value("stroke-width".to_owned()));
        }
        let join = match self.join {
            Join::Miter { .. } => Join::Miter {
                limit: (self.miter * 100_000.0).round() as u32,
            },
            other => other,
        };
        Ok(Some(Stroke {
            width,
            paint: Solid {
                rgb,
                alpha: alpha(self.stroke_alpha),
            },
            cap: self.cap,
            join,
        }))
    }
}

/// `none` or a hex colour; keywords and functions are outside the subset.
fn paint(value: &str) -> Option<Option<[u8; 3]>> {
    if value == "none" {
        return Some(None);
    }
    let hex = value.strip_prefix('#')?;
    let digit = |at: usize| u8::from_str_radix(hex.get(at..=at)?, 16).ok();
    let byte = |at: usize| u8::from_str_radix(hex.get(at..at + 2)?, 16).ok();
    match hex.len() {
        3 => Some(Some([digit(0)? * 17, digit(1)? * 17, digit(2)? * 17])),
        6 => Some(Some([byte(0)?, byte(2)?, byte(4)?])),
        _ => None,
    }
}

fn unit(value: &str) -> Option<f64> {
    path::number(value).filter(|v| (0.0..=1.0).contains(v))
}

fn alpha(opacity: f64) -> u32 {
    (opacity * 100_000.0).round() as u32
}

struct Compiler<'t> {
    tree: &'t XmlTree,
    resources: &'t Resources,
    view: Rect,
    shapes: Vec<NativeShape>,
}

impl Compiler<'_> {
    /// Compile `root`'s children in document order. Each open group waits
    /// on a heap stack with its next child, the style and the transform it
    /// passes down, so nesting costs memory, reserved, not call stack.
    fn children(
        &mut self,
        root: usize,
        style: &Style,
        transform: Affine,
    ) -> Result<(), GraphicError> {
        let tree = self.tree;
        let mut open: Vec<(usize, usize, Style, Affine)> = vec![(root, 0, *style, transform)];
        while let Some(&(parent, next, style, transform)) = open.last() {
            let Some(&at) = tree.nodes[parent].children.get(next) else {
                open.pop();
                continue;
            };
            if let Some(top) = open.last_mut() {
                top.1 = next + 1;
            }
            let node = &tree.nodes[at];
            self.resources
                .checkpoint()
                .map_err(GraphicError::Resource)?;
            if node.namespace != SVG_NS {
                return Err(refuse(at, node, Refused::Element));
            }
            let own: &[&str] = match node.name.as_str() {
                "title" | "desc" => {
                    allowed(at, node, &["id"], false)?;
                    if let Some(&child) = node.children.first() {
                        return Err(refuse(child, &tree.nodes[child], Refused::Element));
                    }
                    continue;
                }
                "g" => &["transform"],
                "rect" => &["transform", "x", "y", "width", "height", "rx", "ry"],
                "circle" => &["transform", "cx", "cy", "r"],
                "ellipse" => &["transform", "cx", "cy", "rx", "ry"],
                "line" => &["transform", "x1", "y1", "x2", "y2"],
                "polyline" | "polygon" => &["transform", "points"],
                "path" => &["transform", "d"],
                _ => return Err(refuse(at, node, Refused::Element)),
            };
            allowed(at, node, own, true)?;
            let style = style.inherit(at, node)?;
            let local = match node.attr("transform") {
                Some(value) => {
                    path::transform(value).map_err(|refused| refuse(at, node, refused))?
                }
                None => Affine::IDENTITY,
            };
            let transform = transform.then(local);
            if node.name == "g" {
                // The group's frame, reserved before the stack grows.
                let _hold = self
                    .resources
                    .reserve(bytes_of::<(usize, usize, Style, Affine)>(2))
                    .map_err(GraphicError::Resource)?;
                open.push((at, 0, style, transform));
            } else {
                self.shape(node, &style, transform)
                    .map_err(|refused| refuse(at, node, refused))?;
            }
        }
        Ok(())
    }

    fn shape(&mut self, node: &Node, style: &Style, transform: Affine) -> Result<(), Refused> {
        let linear = Linear::of(transform).ok_or(Refused::Transform)?;
        let stroke = style.stroke(linear)?;
        let mut fill = style.fill();
        let (frame, geometry, corners) = match node.name.as_str() {
            "rect" => {
                let (frame, preset) = geometry::rect(node, transform, linear)?;
                let corners = if preset == Preset::Rect {
                    std::f64::consts::SQRT_2
                } else {
                    1.0
                };
                (frame, Geometry::Preset(preset), corners)
            }
            "circle" | "ellipse" => (
                geometry::ellipse(node, transform, linear)?,
                Geometry::Preset(Preset::Ellipse),
                1.0,
            ),
            "line" => {
                fill = None;
                (
                    geometry::line(node, transform)?,
                    Geometry::Preset(Preset::Line),
                    1.0,
                )
            }
            _ => {
                let subpaths = geometry::subpaths(node)?;
                // The shape's segments, as its spec keeps them, reserved
                // before the spec is built: a count is no refusal.
                let segments = subpaths.iter().map(|sub| sub.segs.len()).sum::<usize>();
                let _hold = self
                    .resources
                    .reserve(bytes_of::<super::Segment>(segments.saturating_mul(2)))
                    .map_err(Refused::Resource)?;
                let (frame, specs) =
                    geometry::custom(&subpaths, transform, fill.is_some(), stroke.is_some())?;
                (frame, Geometry::Custom(specs), f64::INFINITY)
            }
        };
        if fill.is_none() && stroke.is_none() {
            return Ok(());
        }
        let reach = stroke.map_or(0.0, |stroke| {
            let join = match stroke.join {
                Join::Miter { limit } => (f64::from(limit) / 100_000.0).min(corners),
                Join::Round | Join::Bevel => 1.0,
            };
            let cap = if stroke.cap == Cap::Square {
                std::f64::consts::SQRT_2
            } else {
                1.0
            };
            stroke.width as f64 / 2.0 * join.max(cap)
        });
        if !self.inside(&frame, reach) {
            return Err(Refused::Bounds);
        }
        if let Geometry::Custom(specs) = &geometry {
            for spec in specs.iter().filter(|spec| spec.fill) {
                if !geometry::one_outline(&spec.segments, self.resources)? {
                    return Err(Refused::FillRule);
                }
            }
        }
        self.shapes.push(NativeShape {
            name: node
                .attr("id")
                .map_or_else(|| node.name.clone(), str::to_owned),
            frame,
            geometry,
            fill,
            stroke,
        });
        Ok(())
    }

    /// Whether the frame's outline, rotated and widened by `reach`, stays in
    /// the viewBox: SVG clips at the viewport, a DrawingML group does not.
    fn inside(&self, frame: &Frame, reach: f64) -> bool {
        let r = frame.rect;
        let (hw, hh) = (r.cx as f64 / 2.0, r.cy as f64 / 2.0);
        let (cx, cy) = (r.x as f64 + hw, r.y as f64 + hh);
        let (sin, cos) = (f64::from(frame.rot) / 60_000.0).to_radians().sin_cos();
        let ex = hw * cos.abs() + hh * sin.abs() + reach - SLACK;
        let ey = hw * sin.abs() + hh * cos.abs() + reach - SLACK;
        let view = self.view;
        cx - ex >= view.x as f64
            && cy - ey >= view.y as f64
            && cx + ex <= (view.x + view.cx) as f64
            && cy + ey <= (view.y + view.cy) as f64
    }
}
