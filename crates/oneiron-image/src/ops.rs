//! The edit ops: each changes the body only, never pixels.

use oneiron_organ_protocol::{ErrorCode, Locator, OrganError};

use crate::body::{Filter, ImageBody, Overlay, Shape, Size, Step, Stroke, bad, check_overlay};

/// What one op did: the new body and the units it touched.
#[derive(Debug)]
pub(crate) struct Edited {
    pub(crate) body: ImageBody,
    pub(crate) touched: Vec<Locator>,
}

fn pixels(x: u32, y: u32, w: u32, h: u32) -> Locator {
    Locator::Pixel {
        layer: None,
        x,
        y,
        w,
        h,
    }
}

/// The locator of one overlay.
#[must_use]
pub fn overlay_locator(id: u32) -> Locator {
    Locator::Object {
        id: format!("overlay/{id}"),
    }
}

fn pixel_count(size: Size) -> u64 {
    u64::from(size.w).saturating_mul(u64::from(size.h))
}

/// Bytes a canvas of `size` takes as RGBA.
pub(crate) fn rgba_bytes(size: Size) -> u64 {
    pixel_count(size).saturating_mul(4)
}

/// What a bilinear resize from `from` to `to` holds at its peak: the
/// premultiplied float copy, the vertical pass, the float result and the
/// RGBA result.
pub(crate) fn bilinear_bytes(from: Size, to: Size) -> u64 {
    let float = |w: u32, h: u32| pixel_count(Size { w, h }).saturating_mul(16);
    float(from.w, from.h)
        .saturating_add(float(from.w, to.h))
        .saturating_add(float(to.w, to.h))
        .saturating_add(rgba_bytes(to))
}

/// The most bytes rendering and exporting `body` holds at once: the decoded
/// source throughout; at each step the canvas it reads (once it is no longer
/// the source) and what it makes; then the final canvas with an overlay
/// mask, or with the encoder's RGB copy and its output.
///
/// # Errors
/// `bad_request` if a step does not fit.
pub(crate) fn render_peak(body: &ImageBody) -> Result<u64, OrganError> {
    let source = Size {
        w: body.source.width,
        h: body.source.height,
    };
    let mut canvas = source;
    let mut owned = 0u64;
    let mut peak = 0u64;
    for step in &body.steps {
        let next = step.apply_to(canvas)?;
        let made = match step {
            Step::Crop { .. }
            | Step::Resize {
                filter: Filter::Nearest,
                ..
            } => rgba_bytes(next),
            Step::Resize {
                filter: Filter::Bilinear,
                ..
            } => bilinear_bytes(canvas, next),
        };
        peak = peak.max(owned.saturating_add(made));
        owned = rgba_bytes(next);
        canvas = next;
    }
    // With no steps, painting starts from a copy of the source.
    let last = rgba_bytes(canvas);
    let mask = if body.overlays.is_empty() {
        0
    } else {
        pixel_count(canvas)
    };
    // The encoder streams: its output (sized up front to the stored size),
    // its compressor and three rows; never a second whole image.
    let encode = crate::render::png_bound(canvas.w, canvas.h, 4)
        .saturating_add(3 * (4 * u64::from(canvas.w) + 1))
        .saturating_add(1 << 20);
    peak = peak.max(last.saturating_add(mask.max(encode)));
    Ok(rgba_bytes(source).saturating_add(peak))
}

/// Keeps `x, y, w, h` of the canvas. Overlays move with the pixels; one
/// that now crosses the edge is marked clipped.
///
/// # Errors
/// `bad_request` if the rect does not fit the canvas.
pub(crate) fn crop(
    mut body: ImageBody,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
) -> Result<Edited, OrganError> {
    let step = Step::Crop { x, y, w, h };
    body.canvas = step.apply_to(body.canvas)?;
    body.steps.push(step);
    let mut touched = vec![pixels(x, y, w, h)];
    for overlay in &mut body.overlays {
        overlay.shape.translate(-(x as f32), -(y as f32));
        let clipped = overlay.clipped_by(body.canvas);
        if clipped && !overlay.clipped {
            touched.push(overlay_locator(overlay.id));
        }
        overlay.clipped = clipped;
    }
    body.check()?;
    crate::render::check_paint(&body)?;
    Ok(Edited { body, touched })
}

/// Scales the canvas to `w x h`. Overlay points scale per axis and stroke
/// widths by the geometric mean, never under one pixel.
///
/// # Errors
/// `bad_request` for a zero size or an overlay pushed out of range,
/// `too_large` if exporting the result would need more than `max_bytes`.
pub(crate) fn resize(
    mut body: ImageBody,
    w: u32,
    h: u32,
    filter: Filter,
    max_bytes: u64,
) -> Result<Edited, OrganError> {
    let from = body.canvas;
    let step = Step::Resize { w, h, filter };
    let to = step.apply_to(from)?;
    body.canvas = to;
    body.steps.push(step);
    let peak = render_peak(&body)?;
    if peak > max_bytes {
        return Err(OrganError::new(
            ErrorCode::TooLarge,
            format!(
                "after resizing {}x{} to {w}x{h}, export needs {peak} bytes; this organ holds {max_bytes}",
                from.w, from.h
            ),
        ));
    }
    let sx = w as f32 / from.w as f32;
    let sy = h as f32 / from.h as f32;
    let widen = (sx * sy).sqrt();
    for overlay in &mut body.overlays {
        overlay.shape.scale(sx, sy);
        overlay.stroke.width =
            (overlay.stroke.width * widen).clamp(1.0, crate::body::MAX_STROKE_WIDTH);
        overlay.clipped = overlay.clipped_by(to);
    }
    body.check()?;
    crate::render::check_paint(&body)?;
    Ok(Edited {
        body,
        touched: vec![pixels(0, 0, w, h)],
    })
}

/// Adds one overlay with the next id.
///
/// # Errors
/// `bad_request` for a bad shape or stroke, or a full body.
pub(crate) fn annotate(
    mut body: ImageBody,
    shape: Shape,
    stroke: Stroke,
) -> Result<Edited, OrganError> {
    check_overlay(&shape, &stroke)?;
    if body.overlays.len() >= crate::body::MAX_OVERLAYS {
        return Err(bad("the body holds the most overlays it may"));
    }
    if let Shape::Freehand { points } = &shape
        && body.total_points() + points.len() > crate::body::MAX_TOTAL_POINTS
    {
        return Err(bad("the body holds the most points it may"));
    }
    let id = body.next_overlay;
    body.next_overlay = id
        .checked_add(1)
        .ok_or_else(|| bad("overlay ids are spent"))?;
    let mut overlay = Overlay {
        id,
        shape,
        stroke,
        clipped: false,
    };
    overlay.clipped = overlay.clipped_by(body.canvas);
    let mut touched = vec![overlay_locator(id)];
    let b = overlay.bounds();
    let x0 = b.x0.floor().max(0.0);
    let y0 = b.y0.floor().max(0.0);
    let x1 = b.x1.ceil().min(body.canvas.w as f32);
    let y1 = b.y1.ceil().min(body.canvas.h as f32);
    if x1 > x0 && y1 > y0 {
        touched.push(pixels(
            x0 as u32,
            y0 as u32,
            (x1 - x0) as u32,
            (y1 - y0) as u32,
        ));
    }
    body.overlays.push(overlay);
    crate::render::check_paint(&body)?;
    Ok(Edited { body, touched })
}
