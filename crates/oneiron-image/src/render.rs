//! Export: the only place pixels are made. The decoded source runs through
//! the steps, the overlays are painted on with a round brush, and the result
//! is encoded with no metadata.

use std::borrow::Cow;

use image::codecs::png::PngEncoder;
use image::imageops::{self, FilterType};
use image::{ExtendedColorType, ImageBuffer, ImageEncoder, Rgba, Rgba32FImage, RgbaImage};
use oneiron_organ_protocol::{ErrorCode, OrganError};

use crate::body::{Filter, ImageBody, Overlay, Point, Step};

/// Segments longer than this (or than the brush radius, if wider) are cut so
/// each piece's box stays thin.
const PIECE: f32 = 32.0;

/// Renders `body` over its decoded `source`. `check` runs between steps and
/// returns an error once the call is cancelled.
///
/// # Errors
/// Whatever `check` returns.
pub(crate) fn render(
    source: &RgbaImage,
    body: &ImageBody,
    check: &dyn Fn() -> Result<(), OrganError>,
) -> Result<RgbaImage, OrganError> {
    let mut image = Cow::Borrowed(source);
    for step in &body.steps {
        check()?;
        image = Cow::Owned(match *step {
            Step::Crop { x, y, w, h } => imageops::crop_imm(image.as_ref(), x, y, w, h).to_image(),
            Step::Resize {
                w,
                h,
                filter: Filter::Nearest,
            } => resize_nearest(&image, w, h),
            Step::Resize {
                w,
                h,
                filter: Filter::Bilinear,
            } => resize_bilinear(&image, w, h),
        });
    }
    let mut image = image.into_owned();
    for overlay in &body.overlays {
        check()?;
        paint(&mut image, overlay);
    }
    Ok(image)
}

/// Nearest neighbour, centre-aligned: output `x` reads source
/// `floor((x + 0.5) * W / w)`, in integers.
fn resize_nearest(source: &RgbaImage, w: u32, h: u32) -> RgbaImage {
    let (sw, sh) = source.dimensions();
    let pick = |out: u32, len: u32, from: u32| -> u32 {
        let at = (2 * u64::from(out) + 1) * u64::from(from) / (2 * u64::from(len));
        u32::try_from(at).map_or(from - 1, |at| at.min(from - 1))
    };
    let columns: Vec<u32> = (0..w).map(|x| pick(x, w, sw)).collect();
    ImageBuffer::from_fn(w, h, |x, y| {
        let sy = pick(y, h, sh);
        let sx = columns.get(x as usize).copied().unwrap_or(0);
        *source.get_pixel(sx, sy)
    })
}

/// A triangle (bilinear) filter over premultiplied alpha, so a transparent
/// pixel's colour never bleeds into its neighbours.
fn resize_bilinear(source: &RgbaImage, w: u32, h: u32) -> RgbaImage {
    let (sw, sh) = source.dimensions();
    let premultiplied: Rgba32FImage = ImageBuffer::from_fn(sw, sh, |x, y| {
        let [r, g, b, a] = source.get_pixel(x, y).0.map(|c| f32::from(c) / 255.0);
        Rgba([r * a, g * a, b * a, a])
    });
    let scaled = imageops::resize(&premultiplied, w, h, FilterType::Triangle);
    ImageBuffer::from_fn(w, h, |x, y| {
        let [r, g, b, a] = scaled.get_pixel(x, y).0;
        if a <= 0.0 {
            return Rgba([0, 0, 0, 0]);
        }
        Rgba([to_u8(r / a), to_u8(g / a), to_u8(b / a), to_u8(a)])
    })
}

fn to_u8(unit: f32) -> u8 {
    (unit.clamp(0.0, 1.0) * 255.0).round() as u8
}

/// Paints one overlay: coverage is the distance from each pixel centre to
/// the stroke's segments, with a one-pixel ramp, kept as the maximum over
/// segments so crossings do not darken; then one source-over blend.
fn paint(image: &mut RgbaImage, overlay: &Overlay) {
    let (cw, ch) = image.dimensions();
    let b = overlay.bounds();
    let x0 = clamp_floor(b.x0 - 1.0, cw);
    let y0 = clamp_floor(b.y0 - 1.0, ch);
    let x1 = clamp_ceil(b.x1 + 1.0, cw);
    let y1 = clamp_ceil(b.y1 + 1.0, ch);
    if x1 <= x0 || y1 <= y0 {
        return;
    }
    let (mw, mh) = (x1 - x0, y1 - y0);
    let mut mask = vec![0u8; mw as usize * mh as usize];
    let radius = overlay.stroke.width / 2.0;
    let reach = radius + 1.0;
    for (a, b) in overlay.shape.segments(overlay.stroke.width) {
        let area = (-reach, -reach, cw as f32 + reach, ch as f32 + reach);
        let Some((a, b)) = clip(a, b, area) else {
            continue;
        };
        for (p, q) in pieces(a, b, PIECE.max(radius)) {
            let px0 = clamp_floor(p.x.min(q.x) - radius - 1.0, cw).max(x0);
            let py0 = clamp_floor(p.y.min(q.y) - radius - 1.0, ch).max(y0);
            let px1 = clamp_ceil(p.x.max(q.x) + radius + 1.0, cw).min(x1);
            let py1 = clamp_ceil(p.y.max(q.y) + radius + 1.0, ch).min(y1);
            for y in py0..py1 {
                for x in px0..px1 {
                    let d = distance(x as f32 + 0.5, y as f32 + 0.5, p, q);
                    let cover = to_u8(radius + 0.5 - d);
                    let at = (y - y0) as usize * mw as usize + (x - x0) as usize;
                    if let Some(cell) = mask.get_mut(at) {
                        *cell = (*cell).max(cover);
                    }
                }
            }
        }
    }
    let [r, g, b, a] = overlay.stroke.rgba.map(|c| f32::from(c) / 255.0);
    for y in y0..y1 {
        for x in x0..x1 {
            let at = (y - y0) as usize * mw as usize + (x - x0) as usize;
            let cover = mask.get(at).copied().unwrap_or(0);
            if cover == 0 {
                continue;
            }
            let pixel = image.get_pixel_mut(x, y);
            *pixel = over(*pixel, [r, g, b], a * f32::from(cover) / 255.0);
        }
    }
}

/// Source-over onto a straight-alpha pixel.
fn over(dst: Rgba<u8>, color: [f32; 3], alpha: f32) -> Rgba<u8> {
    let [dr, dg, db, da] = dst.0.map(|c| f32::from(c) / 255.0);
    let out_a = alpha + da * (1.0 - alpha);
    if out_a <= 0.0 {
        return dst;
    }
    let mix = |s: f32, d: f32| (s * alpha + d * da * (1.0 - alpha)) / out_a;
    Rgba([
        to_u8(mix(color[0], dr)),
        to_u8(mix(color[1], dg)),
        to_u8(mix(color[2], db)),
        to_u8(out_a),
    ])
}

fn clamp_floor(value: f32, max: u32) -> u32 {
    value.floor().clamp(0.0, max as f32) as u32
}

fn clamp_ceil(value: f32, max: u32) -> u32 {
    value.ceil().clamp(0.0, max as f32) as u32
}

/// The part of `a..b` inside `(x0, y0, x1, y1)` (Liang-Barsky), so a far-off
/// stroke costs nothing.
fn clip(a: Point, b: Point, (x0, y0, x1, y1): (f32, f32, f32, f32)) -> Option<(Point, Point)> {
    let (dx, dy) = (b.x - a.x, b.y - a.y);
    let (mut t0, mut t1) = (0.0_f32, 1.0_f32);
    for (p, q) in [
        (-dx, a.x - x0),
        (dx, x1 - a.x),
        (-dy, a.y - y0),
        (dy, y1 - a.y),
    ] {
        if p == 0.0 {
            if q < 0.0 {
                return None;
            }
            continue;
        }
        let r = q / p;
        if p < 0.0 {
            t0 = t0.max(r);
        } else {
            t1 = t1.min(r);
        }
        if t0 > t1 {
            return None;
        }
    }
    let at = |t: f32| Point {
        x: a.x + dx * t,
        y: a.y + dy * t,
    };
    Some((at(t0), at(t1)))
}

/// Cuts `a..b` into pieces no longer than `piece`.
fn pieces(a: Point, b: Point, piece: f32) -> Vec<(Point, Point)> {
    let len = (b.x - a.x).hypot(b.y - a.y);
    let count = (len / piece).ceil().max(1.0) as usize;
    let at = |i: usize| {
        let t = i as f32 / count as f32;
        Point {
            x: a.x + (b.x - a.x) * t,
            y: a.y + (b.y - a.y) * t,
        }
    };
    (0..count).map(|i| (at(i), at(i + 1))).collect()
}

/// Distance from `(x, y)` to the segment `p..q`.
fn distance(x: f32, y: f32, p: Point, q: Point) -> f32 {
    let (dx, dy) = (q.x - p.x, q.y - p.y);
    let len2 = dx * dx + dy * dy;
    let t = if len2 > 0.0 {
        (((x - p.x) * dx + (y - p.y) * dy) / len2).clamp(0.0, 1.0)
    } else {
        0.0
    };
    (x - (p.x + t * dx)).hypot(y - (p.y + t * dy))
}

/// Encodes PNG with no metadata: RGB when the source has no alpha (painting
/// never adds transparency), RGBA otherwise.
///
/// # Errors
/// `internal` if the encoder fails.
pub(crate) fn encode_png(image: &RgbaImage, alpha: bool) -> Result<Vec<u8>, OrganError> {
    let (w, h) = image.dimensions();
    let mut out = Vec::new();
    let encoder = PngEncoder::new(&mut out);
    let written = if alpha {
        encoder.write_image(image.as_raw(), w, h, ExtendedColorType::Rgba8)
    } else {
        let rgb: Vec<u8> = image
            .as_raw()
            .chunks_exact(4)
            .flat_map(|px| [px[0], px[1], px[2]])
            .collect();
        encoder.write_image(&rgb, w, h, ExtendedColorType::Rgb8)
    };
    written.map_err(|err| OrganError::new(ErrorCode::Internal, format!("png encode: {err}")))?;
    Ok(out)
}
