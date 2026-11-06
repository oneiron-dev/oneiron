//! A PNG compatibility image for held SVG geometry the native compiler already
//! understands. This is not the graphic compiler's output: callers keep the SVG
//! and name this separate embedding derivation on the export receipt.

use super::{Cap, EMU_PER_PX, Geometry, GraphicLimits, Join, NativeShape, Preset, Segment, Solid};
use crate::design_plan::Rect;
use crate::resource::{Resources, bytes_of, wide};
use std::io::{self, Write};
use tiny_skia::{FillRule, Paint, Path, PathBuilder, Pixmap, Transform};

/// Intrinsic SVG pixels, using the existing 96-dpi mapping. Unsupported input or
/// an unavailable optional raster leaves the held-picture caller's old SVG path.
/// The native compiler reserves its parse/geometry; pixel and output buffers are
/// admitted here. Skia and PNG codec scratch are not measured by this port.
pub(crate) fn held_svg_png(
    bytes: &[u8],
    limits: GraphicLimits,
    resources: &Resources,
) -> Option<(Vec<u8>, [u32; 2])> {
    if bytes.len() > limits.svg_bytes {
        return None;
    }
    resources.checkpoint().ok()?;
    // Placement is not used: Office stretches both the original SVG and the
    // fallback inside the same unchanged picture frame.
    let drawing = super::svg::compile(
        bytes,
        Rect {
            x: 0,
            y: 0,
            cx: EMU_PER_PX,
            cy: EMU_PER_PX,
        },
        resources,
    )
    .ok()?;
    let side = |emu: i64| -> Option<u32> {
        u32::try_from(emu.checked_add(EMU_PER_PX - 1)? / EMU_PER_PX)
            .ok()
            .filter(|n| *n > 0)
    };
    let pixels = [side(drawing.child.cx)?, side(drawing.child.cy)?];
    let count = u64::from(pixels[0]).checked_mul(u64::from(pixels[1]))?;
    if count > limits.raster_pixels {
        return None;
    }
    let size = tiny_skia::IntSize::from_wh(pixels[0], pixels[1])?;
    let length = usize::try_from(count.checked_mul(4)?).ok()?;
    let hold = resources.reserve(wide(length)).ok()?;
    let mut rgba = Vec::new();
    rgba.try_reserve_exact(length).ok()?;
    rgba.resize(length, 0);
    drop(hold);
    let mut pixmap = Pixmap::from_vec(rgba, size)?;
    let unit = EMU_PER_PX as f64;
    let scale = [
        f64::from(pixels[0]) * unit / drawing.child.cx as f64,
        f64::from(pixels[1]) * unit / drawing.child.cy as f64,
    ];
    for shape in &drawing.shapes {
        resources.checkpoint().ok()?;
        let rect = shape.frame.rect;
        let (cx, cy) = (rect.cx as f64 / (2.0 * unit), rect.cy as f64 / (2.0 * unit));
        let (sin, cos) = (f64::from(shape.frame.rot) / 60_000.0)
            .to_radians()
            .sin_cos();
        // Positive rotations are clockwise in both SVG and the y-down pixmap.
        // from_row takes ky before kx; rotate about the native frame centre.
        let transform = Transform::from_row(
            (scale[0] * cos) as f32,
            (scale[1] * sin) as f32,
            (-scale[0] * sin) as f32,
            (scale[1] * cos) as f32,
            (scale[0] * ((rect.x - drawing.child.x) as f64 / unit + cx - cos * cx + sin * cy))
                as f32,
            (scale[1] * ((rect.y - drawing.child.y) as f64 / unit + cy - sin * cx - cos * cy))
                as f32,
        );
        match &shape.geometry {
            Geometry::Preset(preset) => {
                let _hold = resources.reserve_estimate(1024, 0).ok()?;
                let path = preset_path(shape, *preset)?;
                paint(&mut pixmap, &path, shape, true, true, transform);
            }
            Geometry::Custom(specs) => {
                for spec in specs {
                    resources.checkpoint().ok()?;
                    let points = spec
                        .segments
                        .iter()
                        .map(|segment| match segment {
                            Segment::CubicTo(..) => 3,
                            Segment::QuadTo(..) => 2,
                            Segment::MoveTo(..) | Segment::LineTo(..) => 1,
                            Segment::Close => 0,
                        })
                        .sum::<usize>();
                    let _hold = resources
                        .reserve_estimate(
                            bytes_of::<tiny_skia::Point>(points)
                                .saturating_add(wide(spec.segments.len()))
                                .saturating_mul(2),
                            0,
                        )
                        .ok()?;
                    let mut path = PathBuilder::with_capacity(spec.segments.len(), points);
                    for segment in &spec.segments {
                        resources.checkpoint().ok()?;
                        let xy = |p: &super::Pt| {
                            ((p.x as f64 / unit) as f32, (p.y as f64 / unit) as f32)
                        };
                        match segment {
                            Segment::MoveTo(p) => {
                                let (x, y) = xy(p);
                                path.move_to(x, y);
                            }
                            Segment::LineTo(p) => {
                                let (x, y) = xy(p);
                                path.line_to(x, y);
                            }
                            Segment::CubicTo(a, b, c) => {
                                let (x1, y1) = xy(a);
                                let (x2, y2) = xy(b);
                                let (x, y) = xy(c);
                                path.cubic_to(x1, y1, x2, y2, x, y);
                            }
                            Segment::QuadTo(a, b) => {
                                let (x1, y1) = xy(a);
                                let (x, y) = xy(b);
                                path.quad_to(x1, y1, x, y);
                            }
                            Segment::Close => path.close(),
                        }
                    }
                    let path = path.finish()?;
                    paint(&mut pixmap, &path, shape, spec.fill, spec.stroke, transform);
                }
            }
        }
    }
    resources.checkpoint().ok()?;
    // Consume the pixmap before converting premultiplied RGBA to PNG's straight
    // RGBA; there is no second full pixel buffer and no invalid Pixmap value.
    let mut rgba = pixmap.take();
    for row in rgba.chunks_mut(usize::try_from(pixels[0]).ok()?.checked_mul(4)?) {
        resources.checkpoint().ok()?;
        for pixel in row.chunks_exact_mut(4) {
            let color =
                tiny_skia::PremultipliedColorU8::from_rgba(pixel[0], pixel[1], pixel[2], pixel[3])?
                    .demultiply();
            pixel.copy_from_slice(&[color.red(), color.green(), color.blue(), color.alpha()]);
        }
    }
    let mut output = PngBytes {
        bytes: Vec::new(),
        resources,
        limit: limits.raster_bytes,
    };
    let mut encoder = png::Encoder::new(&mut output, pixels[0], pixels[1]);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().ok()?;
    writer.write_image_data(&rgba).ok()?;
    writer.finish().ok()?;
    resources.checkpoint().ok()?;
    Some((output.bytes, pixels))
}

fn paint(
    pixmap: &mut Pixmap,
    path: &Path,
    shape: &NativeShape,
    fill: bool,
    stroke: bool,
    transform: Transform,
) {
    let paint = |solid: Solid| {
        let mut paint = Paint::default();
        paint.set_color_rgba8(
            solid.rgb[0],
            solid.rgb[1],
            solid.rgb[2],
            ((u64::from(solid.alpha) * 255 + 50_000) / 100_000) as u8,
        );
        paint.anti_alias = true;
        paint
    };
    if let Some(solid) = shape.fill.filter(|_| fill) {
        pixmap.fill_path(path, &paint(solid), FillRule::Winding, transform, None);
    }
    if let Some(stroke) = shape.stroke.filter(|_| stroke) {
        let (line_join, miter_limit) = match stroke.join {
            Join::Miter { limit } => (tiny_skia::LineJoin::Miter, limit as f32 / 100_000.0),
            Join::Round => (tiny_skia::LineJoin::Round, 4.0),
            Join::Bevel => (tiny_skia::LineJoin::Bevel, 4.0),
        };
        let stroke_style = tiny_skia::Stroke {
            width: (stroke.width as f64 / EMU_PER_PX as f64) as f32,
            line_cap: match stroke.cap {
                Cap::Flat => tiny_skia::LineCap::Butt,
                Cap::Round => tiny_skia::LineCap::Round,
                Cap::Square => tiny_skia::LineCap::Square,
            },
            line_join,
            miter_limit,
            dash: None,
        };
        pixmap.stroke_path(path, &paint(stroke.paint), &stroke_style, transform, None);
    }
}

fn preset_path(shape: &NativeShape, preset: Preset) -> Option<Path> {
    let unit = EMU_PER_PX as f64;
    let w = (shape.frame.rect.cx as f64 / unit) as f32;
    let h = (shape.frame.rect.cy as f64 / unit) as f32;
    let rect = || tiny_skia::Rect::from_xywh(0.0, 0.0, w, h);
    let mut path = PathBuilder::new();
    match preset {
        Preset::Rect => path.push_rect(rect()?),
        Preset::Ellipse => path.push_oval(rect()?),
        Preset::Line => {
            path.move_to(0.0, if shape.frame.flip_v { h } else { 0.0 });
            path.line_to(w, if shape.frame.flip_v { 0.0 } else { h });
        }
        Preset::RoundRect { adj } => {
            let r = w.min(h) * adj as f32 / 100_000.0;
            // Standard cubic approximation of a quarter circle.
            let k = (4.0 / 3.0 * std::f64::consts::FRAC_PI_8.tan()) as f32 * r;
            path.move_to(r, 0.0);
            path.line_to(w - r, 0.0);
            path.cubic_to(w - r + k, 0.0, w, r - k, w, r);
            path.line_to(w, h - r);
            path.cubic_to(w, h - r + k, w - r + k, h, w - r, h);
            path.line_to(r, h);
            path.cubic_to(r - k, h, 0.0, h - r + k, 0.0, h - r);
            path.line_to(0.0, r);
            path.cubic_to(0.0, r - k, r - k, 0.0, r, 0.0);
            path.close();
        }
    }
    path.finish()
}

struct PngBytes<'a> {
    bytes: Vec<u8>,
    resources: &'a Resources,
    limit: usize,
}

impl Write for PngBytes<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.resources.checkpoint().map_err(io::Error::other)?;
        let end = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|end| *end <= self.limit)
            .ok_or_else(|| io::Error::other("optional raster byte ceiling"))?;
        if end > self.bytes.capacity() {
            let _hold = self
                .resources
                .reserve(wide(end - self.bytes.capacity()))
                .map_err(io::Error::other)?;
            self.bytes
                .try_reserve_exact(end - self.bytes.len())
                .map_err(io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
