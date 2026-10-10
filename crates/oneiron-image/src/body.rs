//! The `image` kind's typed body, schema 1.
//!
//! The body is non-destructive: it names the source by content hash, then
//! lists the steps and overlays a person or agent added. Pixels are only
//! made at export. Every coordinate is in canvas pixels after the steps
//! before it, top-left origin, after EXIF orientation.

use oneiron_organ_protocol::{ErrorCode, Hash32, OrganError, TypedBody};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The body kind this organ reads and writes.
pub const KIND: &str = "image";
/// The body schema this organ speaks.
pub const SCHEMA: u32 = 1;

/// The longest side a source or any step's canvas may have.
pub const MAX_SIDE: u32 = 65_535;
/// The most steps one body may carry.
pub const MAX_STEPS: usize = 256;
/// The most overlays one body may carry.
pub const MAX_OVERLAYS: usize = 1024;
/// The most points one freehand overlay may carry.
pub const MAX_POINTS: usize = 16_384;
/// The most freehand points one body may carry, so a body stays well inside
/// the protocol's per-frame value bound (a point is five values).
pub const MAX_TOTAL_POINTS: usize = 131_072;
/// The widest stroke, in canvas pixels.
pub const MAX_STROKE_WIDTH: f32 = 1024.0;
/// How far an overlay coordinate may sit from the canvas.
const MAX_COORD: f32 = 16_777_216.0;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageBody {
    pub source: Source,
    /// The canvas after every step.
    pub canvas: Size,
    pub steps: Vec<Step>,
    pub overlays: Vec<Overlay>,
    /// The id the next overlay gets.
    pub next_overlay: u32,
}

/// The original image, kept as the vault holds it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Source {
    pub hash: Hash32,
    pub media_type: String,
    pub format: Format,
    /// Width after EXIF orientation.
    pub width: u32,
    /// Height after EXIF orientation.
    pub height: u32,
    /// The EXIF orientation applied at decode, 1 to 8.
    pub orientation: u8,
    pub alpha: bool,
    pub icc: Icc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Png,
    Jpeg,
    Webp,
}

impl Format {
    #[must_use]
    pub fn media_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Webp => "image/webp",
        }
    }
}

/// The source's colour profile. Untagged input is read as sRGB, and the
/// organ says so in its notes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Icc {
    None,
    Srgb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Size {
    pub w: u32,
    pub h: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Step {
    Crop { x: u32, y: u32, w: u32, h: u32 },
    Resize { w: u32, h: u32, filter: Filter },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Filter {
    Nearest,
    Bilinear,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Overlay {
    pub id: u32,
    pub shape: Shape,
    pub stroke: Stroke,
    /// Part of the overlay lies outside the canvas; export cuts it there.
    pub clipped: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Shape {
    /// An outline, not a fill.
    Rect {
        x: f32,
        y: f32,
        w: f32,
        h: f32,
    },
    Arrow {
        from: Point,
        to: Point,
    },
    Freehand {
        points: Vec<Point>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub x: f32,
    pub y: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Stroke {
    /// Straight (not premultiplied) sRGB plus alpha.
    pub rgba: [u8; 4],
    pub width: f32,
}

/// An axis-aligned box in canvas pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Bounds {
    pub(crate) x0: f32,
    pub(crate) y0: f32,
    pub(crate) x1: f32,
    pub(crate) y1: f32,
}

pub(crate) fn bad(detail: impl Into<String>) -> OrganError {
    OrganError::new(ErrorCode::BadRequest, detail)
}

/// A value as MessagePack with named fields, so any reader can follow it.
///
/// # Errors
/// `internal` if the value does not encode.
pub(crate) fn to_value<T: Serialize>(value: &T) -> Result<rmpv::Value, OrganError> {
    let bytes = rmp_serde::to_vec_named(value)
        .map_err(|err| OrganError::new(ErrorCode::Internal, format!("encode: {err}")))?;
    rmpv::decode::read_value(&mut bytes.as_slice())
        .map_err(|err| OrganError::new(ErrorCode::Internal, format!("encode: {err}")))
}

/// # Errors
/// `bad_request` naming `what` if the value does not have the shape.
pub(crate) fn from_value<T: DeserializeOwned>(
    value: &rmpv::Value,
    what: &str,
) -> Result<T, OrganError> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|err| bad(format!("{what}: {err}")))?;
    rmp_serde::from_slice(&bytes).map_err(|err| bad(format!("{what}: {err}")))
}

impl ImageBody {
    /// A fresh body over `source`: no steps, no overlays.
    #[must_use]
    pub fn new(source: Source) -> Self {
        Self {
            canvas: Size {
                w: source.width,
                h: source.height,
            },
            source,
            steps: Vec::new(),
            overlays: Vec::new(),
            next_overlay: 0,
        }
    }

    /// Reads and checks a body.
    ///
    /// # Errors
    /// `schema_mismatch` for another kind or schema; `bad_request` for a body
    /// that does not parse or does not add up.
    pub fn from_typed(body: Option<&TypedBody>) -> Result<Self, OrganError> {
        let body = body.ok_or_else(|| bad("this verb needs an image body"))?;
        if body.kind != KIND || body.schema != SCHEMA {
            return Err(OrganError::new(
                ErrorCode::SchemaMismatch,
                format!(
                    "the image organ reads {KIND} schema {SCHEMA}, not {} schema {}",
                    body.kind, body.schema
                ),
            ));
        }
        let parsed: Self = from_value(&body.value, "image body")?;
        parsed.check()?;
        Ok(parsed)
    }

    /// # Errors
    /// `internal` if the body does not encode.
    pub fn to_typed(&self) -> Result<TypedBody, OrganError> {
        Ok(TypedBody {
            kind: KIND.to_owned(),
            schema: SCHEMA,
            value: to_value(self)?,
        })
    }

    /// Replays the steps from the source size and checks every bound, so a
    /// body that reaches export always renders. Every edit checks the body
    /// it returns too.
    pub(crate) fn check(&self) -> Result<(), OrganError> {
        if !(1..=8).contains(&self.source.orientation) {
            return Err(bad("orientation must be 1 to 8"));
        }
        if self.steps.len() > MAX_STEPS {
            return Err(bad(format!("more than {MAX_STEPS} steps")));
        }
        if self.overlays.len() > MAX_OVERLAYS {
            return Err(bad(format!("more than {MAX_OVERLAYS} overlays")));
        }
        let mut canvas = Size {
            w: self.source.width,
            h: self.source.height,
        };
        if canvas.w == 0 || canvas.h == 0 {
            return Err(bad("the source has no pixels"));
        }
        if canvas.w > MAX_SIDE || canvas.h > MAX_SIDE {
            return Err(bad(format!(
                "the source is wider or taller than {MAX_SIDE}"
            )));
        }
        for step in &self.steps {
            canvas = step.apply_to(canvas)?;
        }
        if canvas != self.canvas {
            return Err(bad("the canvas does not match the steps"));
        }
        if self.total_points() > MAX_TOTAL_POINTS {
            return Err(bad(format!("more than {MAX_TOTAL_POINTS} points in all")));
        }
        let mut ids = std::collections::BTreeSet::new();
        for overlay in &self.overlays {
            check_overlay(&overlay.shape, &overlay.stroke)?;
            if overlay.id >= self.next_overlay || !ids.insert(overlay.id) {
                return Err(bad(format!("overlay id {} is reused", overlay.id)));
            }
            if overlay.clipped != overlay.clipped_by(self.canvas) {
                return Err(bad(format!(
                    "overlay {} says clipped is {}, but its bounds say otherwise",
                    overlay.id, overlay.clipped
                )));
            }
        }
        Ok(())
    }
}

impl ImageBody {
    /// Freehand points across every overlay.
    #[must_use]
    pub fn total_points(&self) -> usize {
        self.overlays
            .iter()
            .map(|overlay| match &overlay.shape {
                Shape::Freehand { points } => points.len(),
                Shape::Rect { .. } | Shape::Arrow { .. } => 0,
            })
            .sum()
    }
}

impl Step {
    /// The canvas after this step.
    ///
    /// # Errors
    /// `bad_request` if the step does not fit `canvas`.
    pub(crate) fn apply_to(self, canvas: Size) -> Result<Size, OrganError> {
        match self {
            Self::Crop { x, y, w, h } => {
                let fits = w > 0
                    && h > 0
                    && x.checked_add(w).is_some_and(|end| end <= canvas.w)
                    && y.checked_add(h).is_some_and(|end| end <= canvas.h);
                if !fits {
                    return Err(bad(format!(
                        "crop {x},{y} {w}x{h} does not fit the {}x{} canvas",
                        canvas.w, canvas.h
                    )));
                }
                Ok(Size { w, h })
            }
            Self::Resize { w, h, .. } => {
                if w == 0 || h == 0 {
                    return Err(bad("resize to zero pixels"));
                }
                if w > MAX_SIDE || h > MAX_SIDE {
                    return Err(OrganError::new(
                        ErrorCode::TooLarge,
                        format!("resize to {w}x{h}: a side is past {MAX_SIDE}"),
                    ));
                }
                Ok(Size { w, h })
            }
        }
    }
}

/// # Errors
/// `bad_request` for a non-finite or far-off coordinate, a stroke out of
/// range, or a freehand line with no points or too many.
pub(crate) fn check_overlay(shape: &Shape, stroke: &Stroke) -> Result<(), OrganError> {
    if !(stroke.width.is_finite() && (1.0..=MAX_STROKE_WIDTH).contains(&stroke.width)) {
        return Err(bad(format!("stroke width must be 1 to {MAX_STROKE_WIDTH}")));
    }
    if let Shape::Freehand { points } = shape
        && (points.is_empty() || points.len() > MAX_POINTS)
    {
        return Err(bad(format!("a freehand line has 1 to {MAX_POINTS} points")));
    }
    if let Shape::Rect { w, h, .. } = shape
        && !(*w >= 0.0 && *h >= 0.0)
    {
        return Err(bad("a rect needs a non-negative size"));
    }
    let near = |value: f32| value.is_finite() && value.abs() <= MAX_COORD;
    let ok = match shape {
        Shape::Rect { x, y, w, h } => [*x, *y, *w, *h].into_iter().all(near),
        Shape::Arrow { from, to } => [from.x, from.y, to.x, to.y].into_iter().all(near),
        Shape::Freehand { points } => points.iter().all(|p| near(p.x) && near(p.y)),
    };
    if ok {
        Ok(())
    } else {
        Err(bad("an overlay coordinate is not finite or is too far out"))
    }
}

impl Shape {
    /// Moves every point by `(dx, dy)`.
    pub(crate) fn translate(&mut self, dx: f32, dy: f32) {
        self.map_points(|p| Point {
            x: p.x + dx,
            y: p.y + dy,
        });
    }

    /// Scales every point per axis about the origin.
    pub(crate) fn scale(&mut self, sx: f32, sy: f32) {
        self.map_points(|p| Point {
            x: p.x * sx,
            y: p.y * sy,
        });
    }

    fn map_points(&mut self, f: impl Fn(Point) -> Point) {
        match self {
            Self::Rect { x, y, w, h } => {
                let from = f(Point { x: *x, y: *y });
                let to = f(Point {
                    x: *x + *w,
                    y: *y + *h,
                });
                *x = from.x;
                *y = from.y;
                *w = to.x - from.x;
                *h = to.y - from.y;
            }
            Self::Arrow { from, to } => {
                *from = f(*from);
                *to = f(*to);
            }
            Self::Freehand { points } => {
                for point in points.iter_mut() {
                    *point = f(*point);
                }
            }
        }
    }

    /// The segments a stroke follows. A rect is its four edges, an arrow is
    /// its shaft and two head barbs, a freehand line joins its points (one
    /// point is a dot).
    pub(crate) fn segments(&self, width: f32) -> Vec<(Point, Point)> {
        match self {
            Self::Rect { x, y, w, h } => {
                let a = Point { x: *x, y: *y };
                let b = Point { x: *x + *w, y: *y };
                let c = Point {
                    x: *x + *w,
                    y: *y + *h,
                };
                let d = Point { x: *x, y: *y + *h };
                vec![(a, b), (b, c), (c, d), (d, a)]
            }
            Self::Arrow { from, to } => {
                let mut segments = vec![(*from, *to)];
                let (dx, dy) = (from.x - to.x, from.y - to.y);
                let len = dx.hypot(dy);
                if len > 0.0 {
                    let barb = (3.0 * width).max(8.0).min(len);
                    let (ux, uy) = (dx / len, dy / len);
                    // Two barbs at 30 degrees either side of the shaft.
                    let (sin, cos) = (0.5_f32, 0.866_025_4_f32);
                    for side in [1.0_f32, -1.0] {
                        let rx = ux * cos - side * uy * sin;
                        let ry = side * ux * sin + uy * cos;
                        let tip = Point {
                            x: to.x + rx * barb,
                            y: to.y + ry * barb,
                        };
                        segments.push((*to, tip));
                    }
                }
                segments
            }
            Self::Freehand { points } => match points.as_slice() {
                [only] => vec![(*only, *only)],
                many => many.windows(2).map(|pair| (pair[0], pair[1])).collect(),
            },
        }
    }
}

impl Overlay {
    /// Everything the stroke paints, before the canvas cuts it.
    pub(crate) fn bounds(&self) -> Bounds {
        let reach = self.stroke.width / 2.0;
        let mut bounds = Bounds {
            x0: f32::INFINITY,
            y0: f32::INFINITY,
            x1: f32::NEG_INFINITY,
            y1: f32::NEG_INFINITY,
        };
        for (a, b) in self.shape.segments(self.stroke.width) {
            for p in [a, b] {
                bounds.x0 = bounds.x0.min(p.x - reach);
                bounds.y0 = bounds.y0.min(p.y - reach);
                bounds.x1 = bounds.x1.max(p.x + reach);
                bounds.y1 = bounds.y1.max(p.y + reach);
            }
        }
        bounds
    }

    /// Whether export cuts part of this overlay at `canvas`.
    pub(crate) fn clipped_by(&self, canvas: Size) -> bool {
        let b = self.bounds();
        b.x0 < 0.0 || b.y0 < 0.0 || b.x1 > canvas.w as f32 || b.y1 > canvas.h as f32
    }
}
