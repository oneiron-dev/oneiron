use super::*;

/// Whether the square of [`CLICK_CHECK_RADIUS`] around screenshot pixel
/// (`across`, `down`) looks in `now` as it did in `then`: an image of the
/// same size, with at most [`CLICK_CHECK_SLACK`] of the square's pixels
/// changed. The rest of the window may change (a caret, an animation).
pub(super) fn looks_as_it_did(
    then: &[u8],
    now: &[u8],
    across: f64,
    down: f64,
) -> Result<bool, BrowserError> {
    let decode = |png: &[u8]| {
        image::load_from_memory(png)
            .map(|image| image.to_rgba8())
            .map_err(|e| BrowserError::Protocol(e.to_string()))
    };
    let (then, now) = (decode(then)?, decode(now)?);
    let (width, height) = then.dimensions();
    if (width, height) != now.dimensions() || width == 0 || height == 0 {
        return Ok(false);
    }
    // `across` and `down` are inside the window's pixels, never negative.
    let (x, y) = (
        (across as u32).min(width - 1),
        (down as u32).min(height - 1),
    );
    let columns = x.saturating_sub(CLICK_CHECK_RADIUS)..=(x + CLICK_CHECK_RADIUS).min(width - 1);
    let rows = y.saturating_sub(CLICK_CHECK_RADIUS)..=(y + CLICK_CHECK_RADIUS).min(height - 1);
    let (mut seen, mut changed) = (0u32, 0u32);
    for row in rows {
        for column in columns.clone() {
            seen += 1;
            if then.get_pixel(column, row) != now.get_pixel(column, row) {
                changed += 1;
            }
        }
    }
    Ok(f64::from(changed) <= f64::from(seen) * CLICK_CHECK_SLACK)
}

/// Blacks out a window's secret fields in its screenshot, before the image
/// is held. A secret field the screenshot cannot place refuses the image.
pub(super) fn mask(
    png: Vec<u8>,
    bounds: Rect,
    scale: f64,
    secrets: &[Secret],
) -> Result<Vec<u8>, BrowserError> {
    if secrets.is_empty() {
        return Ok(png);
    }
    let mut image = image::load_from_memory(&png)
        .map_err(|e| BrowserError::Protocol(e.to_string()))?
        .to_rgba8();
    let (width, height) = image.dimensions();
    for secret in secrets {
        let rect = secret
            .shot
            .or_else(|| {
                secret.screen.map(|frame| Rect {
                    x: (frame.x - bounds.x) * scale,
                    y: (frame.y - bounds.y) * scale,
                    w: frame.w * scale,
                    h: frame.h * scale,
                })
            })
            .ok_or_else(|| {
                BrowserError::Protocol("a secret field has no place to mask".to_owned())
            })?;
        let span = |from: f64, to: f64, end: u32| {
            let end = f64::from(end);
            (
                from.floor().clamp(0.0, end) as u32,
                to.ceil().clamp(0.0, end) as u32,
            )
        };
        let (x0, x1) = span(rect.x, rect.x + rect.w, width);
        let (y0, y1) = span(rect.y, rect.y + rect.h, height);
        for y in y0..y1 {
            for x in x0..x1 {
                image.put_pixel(x, y, image::Rgba([0, 0, 0, 255]));
            }
        }
    }
    encode_png(&image::DynamicImage::ImageRgba8(image))
}
