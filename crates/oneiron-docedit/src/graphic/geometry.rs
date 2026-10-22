//! Geometry for the closed subset: basic shapes as presets under a kept
//! transform, polylines, polygons and paths as custom geometry, and the
//! fill-rule check that keeps only outlines both SVG rules paint alike.

use super::path::{self, Affine, P, Seg, Subpath};
use super::{EMU_PER_PX, Frame, PathSpec, Preset, Pt, Refused, Segment, ratio};
use crate::design_plan::Rect;
use crate::ooxml::Node;
use crate::resource::{Resources, bytes_of};

/// The longest viewBox side, in px: every coordinate inside fits an i32 EMU.
pub(super) const MAX_PX: f64 = 100_000.0;
/// Relative tolerance when classifying a composed transform.
const EPSILON: f64 = 1e-9;

/// px to EMU; a value far outside any viewBox is refused before it can
/// overflow later arithmetic.
pub(super) fn emu(px: f64) -> Result<i64, Refused> {
    if !px.is_finite() || px.abs() > 4.0 * MAX_PX {
        return Err(Refused::Bounds);
    }
    Ok((px * EMU_PER_PX as f64).round() as i64)
}

pub(super) fn pt(p: P) -> Result<Pt, Refused> {
    Ok(Pt {
        x: emu(p.x)?,
        y: emu(p.y)?,
    })
}

/// A composed transform the subset keeps: a similarity (rotation and uniform
/// scale) or an axis-aligned scale, either with translation.
#[derive(Debug, Clone, Copy)]
pub(super) struct Linear {
    pub(super) sx: f64,
    pub(super) sy: f64,
    /// 60,000ths of a degree, clockwise.
    pub(super) rot: i32,
}

impl Linear {
    pub(super) fn of(t: Affine) -> Option<Self> {
        let scale = t.a.abs().max(t.b.abs()).max(t.c.abs()).max(t.d.abs());
        let near = |v: f64| v.abs() <= EPSILON * scale;
        if !(scale > 0.0 && scale.is_finite()) {
            return None;
        }
        if near(t.a - t.d) && near(t.b + t.c) && t.a * t.d - t.b * t.c > 0.0 {
            let s = t.a.hypot(t.b);
            let rot = (t.b.atan2(t.a).to_degrees() * 60_000.0).round() as i64;
            return Some(Self {
                sx: s,
                sy: s,
                rot: rot.rem_euclid(21_600_000) as i32,
            });
        }
        (near(t.b) && near(t.c) && t.a > 0.0 && t.d > 0.0).then_some(Self {
            sx: t.a,
            sy: t.d,
            rot: 0,
        })
    }
}

pub(super) fn number(node: &Node, name: &str, default: Option<f64>) -> Result<f64, Refused> {
    match node.attr(name) {
        Some(value) => path::number(value),
        None => default,
    }
    .ok_or_else(|| Refused::Value(name.to_owned()))
}

pub(super) fn positive(node: &Node, name: &str) -> Result<f64, Refused> {
    let value = number(node, name, None)?;
    if value > 0.0 {
        Ok(value)
    } else {
        Err(Refused::Value(name.to_owned()))
    }
}

/// An axis-aligned box under a kept transform: its centre moves, its sides
/// scale, and a rotation becomes the frame's own.
pub(super) fn box_frame(
    transform: Affine,
    linear: Linear,
    (x, y, w, h): (f64, f64, f64, f64),
) -> Result<Frame, Refused> {
    let centre = transform.apply(P {
        x: x + w / 2.0,
        y: y + h / 2.0,
    });
    let (hw, hh) = (w * linear.sx / 2.0, h * linear.sy / 2.0);
    let (left, top) = (emu(centre.x - hw)?, emu(centre.y - hh)?);
    Ok(Frame {
        rect: Rect {
            x: left,
            y: top,
            cx: emu(centre.x + hw)? - left,
            cy: emu(centre.y + hh)? - top,
        },
        rot: linear.rot,
        flip_v: false,
    })
}

pub(super) fn rect(
    node: &Node,
    transform: Affine,
    linear: Linear,
) -> Result<(Frame, Preset), Refused> {
    let (x, y) = (number(node, "x", Some(0.0))?, number(node, "y", Some(0.0))?);
    let (w, h) = (positive(node, "width")?, positive(node, "height")?);
    let radius = |name: &str| -> Result<Option<f64>, Refused> {
        if node.attr(name).is_none() {
            return Ok(None);
        }
        let value = number(node, name, None)?;
        if value < 0.0 {
            return Err(Refused::Value(name.to_owned()));
        }
        Ok(Some(value))
    };
    let (rx, ry) = match (radius("rx")?, radius("ry")?) {
        (None, None) => (0.0, 0.0),
        (Some(r), None) | (None, Some(r)) => (r, r),
        (Some(rx), Some(ry)) => (rx, ry),
    };
    let frame = box_frame(transform, linear, (x, y, w, h))?;
    let (rx, ry) = (rx.min(w / 2.0), ry.min(h / 2.0));
    if rx == 0.0 || ry == 0.0 {
        return Ok((frame, Preset::Rect));
    }
    let radius = emu(rx * linear.sx)?;
    if radius != emu(ry * linear.sy)? {
        return Err(Refused::Value("rx".to_owned()));
    }
    let short = frame.rect.cx.min(frame.rect.cy);
    // A corner or frame that rounds below one EMU has no visible radius.
    if radius == 0 || short == 0 {
        return Ok((frame, Preset::Rect));
    }
    Ok((
        frame,
        Preset::RoundRect {
            adj: ratio(i128::from(radius) * 100_000, i128::from(short)),
        },
    ))
}

pub(super) fn ellipse(node: &Node, transform: Affine, linear: Linear) -> Result<Frame, Refused> {
    let (cx, cy) = (
        number(node, "cx", Some(0.0))?,
        number(node, "cy", Some(0.0))?,
    );
    let (rx, ry) = if node.name == "circle" {
        let r = positive(node, "r")?;
        (r, r)
    } else {
        (positive(node, "rx")?, positive(node, "ry")?)
    };
    box_frame(transform, linear, (cx - rx, cy - ry, 2.0 * rx, 2.0 * ry))
}

/// A line's frame spans its ends; the preset runs corner to corner, flipped
/// when the line rises.
pub(super) fn line(node: &Node, transform: Affine) -> Result<Frame, Refused> {
    let end = |x: &str, y: &str| -> Result<Pt, Refused> {
        pt(transform.apply(P {
            x: number(node, x, Some(0.0))?,
            y: number(node, y, Some(0.0))?,
        }))
    };
    let (a, b) = (end("x1", "y1")?, end("x2", "y2")?);
    Ok(Frame {
        rect: Rect {
            x: a.x.min(b.x),
            y: a.y.min(b.y),
            cx: (a.x - b.x).abs(),
            cy: (a.y - b.y).abs(),
        },
        rot: 0,
        flip_v: (b.x - a.x).signum() * (b.y - a.y).signum() < 0,
    })
}

pub(super) fn subpaths(node: &Node) -> Result<Vec<Subpath>, Refused> {
    if node.name == "path" {
        let d = node
            .attr("d")
            .ok_or_else(|| Refused::Value("d".to_owned()))?;
        return path::path_data(d);
    }
    let bad = || Refused::Value("points".to_owned());
    let numbers = node
        .attr("points")
        .and_then(path::numbers)
        .ok_or_else(bad)?;
    if numbers.len() < 4 || !numbers.len().is_multiple_of(2) {
        return Err(bad());
    }
    let mut points = numbers.chunks_exact(2).map(|pair| P {
        x: pair[0],
        y: pair[1],
    });
    let start = points.next().ok_or_else(bad)?;
    Ok(vec![Subpath {
        start,
        segs: points.map(Seg::Line).collect(),
        closed: node.name == "polygon",
    }])
}

/// Custom geometry: points mapped through the whole transform, framed by
/// their bounding box (control points included), one path unit per EMU.
/// A filled outline gets its own closed path, so an open subpath fills as
/// SVG fills it while its stroke stays open.
pub(super) fn custom(
    subpaths: &[Subpath],
    transform: Affine,
    filled: bool,
    stroked: bool,
) -> Result<(Frame, Vec<PathSpec>), Refused> {
    if filled && subpaths.len() != 1 {
        return Err(Refused::FillRule);
    }
    let map = |p: P| pt(transform.apply(p));
    let mut absolute = Vec::with_capacity(subpaths.len());
    for sub in subpaths {
        let mut segments = vec![Segment::MoveTo(map(sub.start)?)];
        for seg in &sub.segs {
            segments.push(match *seg {
                Seg::Line(p) => Segment::LineTo(map(p)?),
                Seg::Cubic(a, b, c) => Segment::CubicTo(map(a)?, map(b)?, map(c)?),
                Seg::Quad(a, b) => Segment::QuadTo(map(a)?, map(b)?),
            });
        }
        if sub.closed {
            segments.push(Segment::Close);
        }
        absolute.push((segments, sub.closed));
    }
    let points: Vec<Pt> = absolute
        .iter()
        .flat_map(|(segments, _)| segments.iter().flat_map(points_of))
        .collect();
    let left = points.iter().map(|p| p.x).min().unwrap_or(0);
    let top = points.iter().map(|p| p.y).min().unwrap_or(0);
    let right = points.iter().map(|p| p.x).max().unwrap_or(0);
    let bottom = points.iter().map(|p| p.y).max().unwrap_or(0);
    let rect = Rect {
        x: left,
        y: top,
        cx: (right - left).max(1),
        cy: (bottom - top).max(1),
    };
    let shift = |p: Pt| Pt {
        x: p.x - left,
        y: p.y - top,
    };
    let local = |segments: &[Segment]| -> Vec<Segment> {
        segments
            .iter()
            .map(|segment| match *segment {
                Segment::MoveTo(p) => Segment::MoveTo(shift(p)),
                Segment::LineTo(p) => Segment::LineTo(shift(p)),
                Segment::CubicTo(a, b, c) => Segment::CubicTo(shift(a), shift(b), shift(c)),
                Segment::QuadTo(a, b) => Segment::QuadTo(shift(a), shift(b)),
                Segment::Close => Segment::Close,
            })
            .collect()
    };
    let spec = |segments: Vec<Segment>, fill: bool, stroke: bool| PathSpec {
        w: rect.cx,
        h: rect.cy,
        fill,
        stroke,
        segments,
    };
    let specs = match absolute.as_slice() {
        [(segments, true)] if filled => vec![spec(local(segments.as_slice()), true, true)],
        [(segments, false)] if filled => {
            let mut closed = local(segments.as_slice());
            closed.push(Segment::Close);
            let mut specs = vec![spec(closed, true, false)];
            if stroked {
                specs.push(spec(local(segments.as_slice()), false, true));
            }
            specs
        }
        _ => {
            let all: Vec<Segment> = absolute
                .iter()
                .flat_map(|(segments, _)| local(segments.as_slice()))
                .collect();
            vec![spec(all, false, true)]
        }
    };
    let frame = Frame {
        rect,
        rot: 0,
        flip_v: false,
    };
    Ok((frame, specs))
}

/// The points [`points_of`] collects, counted without collecting them.
fn point_count(segment: &Segment) -> usize {
    match segment {
        Segment::MoveTo(_) | Segment::LineTo(_) => 1,
        Segment::CubicTo(..) => 3,
        Segment::QuadTo(..) => 2,
        Segment::Close => 0,
    }
}

fn points_of(segment: &Segment) -> Vec<Pt> {
    match *segment {
        Segment::MoveTo(p) | Segment::LineTo(p) => vec![p],
        Segment::CubicTo(a, b, c) => vec![a, b, c],
        Segment::QuadTo(a, b) => vec![a, b],
        Segment::Close => Vec::new(),
    }
}

/// Whether the nonzero and even-odd rules paint one outline alike. A simple
/// polygon has winding one inside and zero outside. A convex control polygon
/// keeps each curve inside its own hull and the hulls apart, so the curved
/// outline is simple too. Anything else is refused, whatever rule it
/// declares, so the output never depends on DrawingML's fill rule. The
/// outline's point count is an observation (FIX 8574): its points are
/// reserved before they are collected, and the quadratic proof stops only
/// at the caller's deadline, never as a fill-rule refusal.
pub(super) fn one_outline(segments: &[Segment], resources: &Resources) -> Result<bool, Refused> {
    let count = segments.iter().map(point_count).sum();
    let _hold = resources
        .reserve(bytes_of::<Pt>(count))
        .map_err(Refused::Resource)?;
    let mut points: Vec<Pt> = segments.iter().flat_map(points_of).collect();
    let curved = segments
        .iter()
        .any(|segment| matches!(segment, Segment::CubicTo(..) | Segment::QuadTo(..)));
    points.dedup();
    if points.len() > 1 && points.first() == points.last() {
        points.pop();
    }
    if points.len() < 3 {
        return Ok(true);
    }
    Ok(simple(&points, resources)? && (!curved || convex(&points)))
}

fn simple(points: &[Pt], resources: &Resources) -> Result<bool, Refused> {
    let n = points.len();
    let edge = |i: usize| (points[i], points[(i + 1) % n]);
    for i in 0..n {
        resources.checkpoint().map_err(Refused::Resource)?;
        for j in i + 1..n {
            let ((a, b), (c, d)) = (edge(i), edge(j));
            if j == i + 1 || (i == 0 && j == n - 1) {
                // Neighbours share a vertex; they may not fold back on it.
                let (shared, p, q) = if j == i + 1 { (b, a, d) } else { (a, b, c) };
                if cross(shared, p, q) == 0 && dot(shared, p, q) > 0 {
                    return Ok(false);
                }
            } else if crosses(a, b, c, d) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Every turn the same way; with `simple`, a convex polygon.
fn convex(points: &[Pt]) -> bool {
    let n = points.len();
    let mut sign = 0;
    for i in 0..n {
        let (a, b, c) = (points[i], points[(i + 1) % n], points[(i + 2) % n]);
        let turn = cross(a, b, c).signum();
        if turn != 0 {
            if sign != 0 && turn != sign {
                return false;
            }
            sign = turn;
        }
    }
    true
}

/// `(p - o) × (q - o)`.
fn cross(o: Pt, p: Pt, q: Pt) -> i128 {
    let (px, py) = (i128::from(p.x - o.x), i128::from(p.y - o.y));
    let (qx, qy) = (i128::from(q.x - o.x), i128::from(q.y - o.y));
    px * qy - py * qx
}

fn dot(o: Pt, p: Pt, q: Pt) -> i128 {
    let (px, py) = (i128::from(p.x - o.x), i128::from(p.y - o.y));
    let (qx, qy) = (i128::from(q.x - o.x), i128::from(q.y - o.y));
    px * qx + py * qy
}

/// Closed segments `ab` and `cd` share a point.
fn crosses(a: Pt, b: Pt, c: Pt, d: Pt) -> bool {
    let (d1, d2) = (cross(c, d, a), cross(c, d, b));
    let (d3, d4) = (cross(a, b, c), cross(a, b, d));
    if d1.signum() * d2.signum() < 0 && d3.signum() * d4.signum() < 0 {
        return true;
    }
    let on = |p: Pt, q: Pt, r: Pt| {
        r.x >= p.x.min(q.x) && r.x <= p.x.max(q.x) && r.y >= p.y.min(q.y) && r.y <= p.y.max(q.y)
    };
    (d1 == 0 && on(c, d, a))
        || (d2 == 0 && on(c, d, b))
        || (d3 == 0 && on(a, b, c))
        || (d4 == 0 && on(a, b, d))
}
