//! Sanitized raster bytes for caller-marked masked reads.
//!
//! `raster` runs only for reads the caller marked masked; Owner and unmarked
//! reads never reach it. It sniffs the actual bytes, re-encodes decodable
//! images as metadata-free PNG, and falls back to format-aware walkers for
//! PNG, JPEG, WebP and GIF when decoding fails.

use image::ImageDecoder;
use oneiron_model::llm::image::ImageBytes;
use std::io::Cursor;

/// What a masked raster read serves for one image.
pub(super) enum Projection {
    /// Sanitized bytes to serve: fresh PNG after a decode, or the same
    /// format with its metadata removed after a walker pass.
    Sanitized(ImageBytes),
    /// Bytes with no available sanitizer; the caller decides the posture.
    Unsupported,
    /// Bytes in a recognized format that failed to sanitize.
    Invalid,
}

/// Sanitized bytes for `image` when the caller marked the read masked.
pub(super) fn raster(image: &ImageBytes) -> Projection {
    let bytes = &image.bytes;
    let Some(format) = sniff(bytes) else {
        return Projection::Unsupported;
    };
    if let Some(png) = decode_to_png(bytes, format) {
        return Projection::Sanitized(ImageBytes {
            bytes: png,
            media_type: "image/png".to_owned(),
        });
    }
    let cleaned = match format {
        image::ImageFormat::Png => scrub_png(bytes).map(|bytes| (bytes, "image/png")),
        image::ImageFormat::Jpeg => scrub_jpeg(bytes).map(|bytes| (bytes, "image/jpeg")),
        image::ImageFormat::WebP => scrub_webp(bytes).map(|bytes| (bytes, "image/webp")),
        image::ImageFormat::Gif => scrub_gif(bytes).map(|bytes| (bytes, "image/gif")),
        _ => None,
    };
    match cleaned {
        Some((bytes, media_type)) => Projection::Sanitized(ImageBytes {
            bytes,
            media_type: media_type.to_owned(),
        }),
        None if matches!(
            format,
            image::ImageFormat::Pnm | image::ImageFormat::Farbfeld | image::ImageFormat::Dds
        ) =>
        {
            Projection::Unsupported
        }
        None => Projection::Invalid,
    }
}

/// The format `bytes` actually hold, from magic bytes rather than any MIME
/// label. Only the enabled masked-read formats count; anything else is `None`.
fn sniff(bytes: &[u8]) -> Option<image::ImageFormat> {
    if let Ok(format) = image::guess_format(bytes) {
        return recognized(format);
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some(image::ImageFormat::Png);
    }
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some(image::ImageFormat::Jpeg);
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some(image::ImageFormat::Gif);
    }
    if bytes.starts_with(b"RIFF") && bytes.len() >= 12 && bytes[8..12] == *b"WEBP" {
        return Some(image::ImageFormat::WebP);
    }
    if is_tiff_magic(bytes) {
        return Some(image::ImageFormat::Tiff);
    }
    if bytes.starts_with(b"BM") {
        return Some(image::ImageFormat::Bmp);
    }
    if bytes.starts_with(&[0, 0, 1, 0]) {
        return Some(image::ImageFormat::Ico);
    }
    None
}

/// `Some` when `format` has a masked-read sanitizer.
fn recognized(format: image::ImageFormat) -> Option<image::ImageFormat> {
    match format {
        image::ImageFormat::Png
        | image::ImageFormat::Jpeg
        | image::ImageFormat::WebP
        | image::ImageFormat::Gif
        | image::ImageFormat::Tiff
        | image::ImageFormat::Bmp
        | image::ImageFormat::Ico
        | image::ImageFormat::Pnm
        | image::ImageFormat::Farbfeld
        | image::ImageFormat::Dds => Some(format),
        _ => None,
    }
}

/// Whether `bytes` open with classic TIFF or BigTIFF magic.
fn is_tiff_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x49, 0x49, 0x2A, 0x00])
        || bytes.starts_with(&[0x4D, 0x4D, 0x00, 0x2A])
        || bytes.starts_with(&[0x49, 0x49, 0x2B, 0x00])
        || bytes.starts_with(&[0x4D, 0x4D, 0x00, 0x2B])
}

/// Fresh PNG bytes for `bytes` in `format`, orientation applied and all
/// metadata left behind; `None` when the decode or the re-encode fails.
fn decode_to_png(bytes: &[u8], format: image::ImageFormat) -> Option<Vec<u8>> {
    let mut decoder = image::ImageReader::with_format(Cursor::new(bytes), format)
        .into_decoder()
        .ok()?;
    let orientation = decoder.orientation().ok();
    let mut decoded = image::DynamicImage::from_decoder(decoder).ok()?;
    if let Some(orientation) = orientation {
        decoded.apply_orientation(orientation);
    }
    let mut out = Cursor::new(Vec::new());
    decoded.write_to(&mut out, image::ImageFormat::Png).ok()?;
    Some(out.into_inner())
}

/// `bytes` as PNG with text, Exif, ICC and unknown chunks removed; `None`
/// when the structure fails its length checks or never reaches IEND.
/// Trailing data past IEND is stripped.
fn scrub_png(bytes: &[u8]) -> Option<Vec<u8>> {
    const SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
    if !bytes.starts_with(SIGNATURE) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(SIGNATURE);
    let mut pos = SIGNATURE.len();
    let mut first = true;
    loop {
        if pos + 8 > bytes.len() {
            return None;
        }
        let len = u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
            as usize;
        let kind = [
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ];
        let total = len.checked_add(12)?;
        if pos.checked_add(total)? > bytes.len() {
            return None;
        }
        if first {
            if kind != *b"IHDR" || len != 13 {
                return None;
            }
            first = false;
        }
        if kind == *b"IHDR"
            || kind == *b"PLTE"
            || kind == *b"tRNS"
            || kind == *b"IDAT"
            || kind == *b"IEND"
        {
            out.extend_from_slice(&bytes[pos..pos + total]);
        }
        pos += total;
        if kind == *b"IEND" {
            if len != 0 {
                return None;
            }
            return Some(out);
        }
    }
}

/// `bytes` as JPEG with APPn and COM segments removed; `None` when the
/// structure fails. Every scan past SOS is walked with stuffed bytes and
/// restarts honored, and trailing data past EOI is stripped.
fn scrub_jpeg(bytes: &[u8]) -> Option<Vec<u8>> {
    if !bytes.starts_with(&[0xFF, 0xD8]) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&[0xFF, 0xD8]);
    let mut pos = 2;
    loop {
        let (marker, after) = jpeg_marker(bytes, pos)?;
        match marker {
            0xD8 => return None,
            0xD9 => {
                out.extend_from_slice(&[0xFF, 0xD9]);
                return Some(out);
            }
            0x01 | 0xD0..=0xD7 => {
                out.extend_from_slice(&[0xFF, marker]);
                pos = after;
            }
            0xDA => {
                let header_end = jpeg_segment_end(bytes, after)?;
                out.extend_from_slice(&[0xFF, marker]);
                out.extend_from_slice(&bytes[after..header_end]);
                let scan_end = jpeg_scan_end(bytes, header_end)?;
                out.extend_from_slice(&bytes[header_end..scan_end]);
                pos = scan_end;
            }
            0xC0..=0xCF | 0xDB..=0xDF | 0xE0..=0xEF | 0xFE => {
                if marker == 0xC8 {
                    return None;
                }
                let end = jpeg_segment_end(bytes, after)?;
                if !matches!(marker, 0xE0..=0xEF | 0xFE) {
                    out.extend_from_slice(&[0xFF, marker]);
                    out.extend_from_slice(&bytes[after..end]);
                }
                pos = end;
            }
            _ => return None,
        }
    }
}

/// The marker at `pos` (one `0xFF`, its fill bytes, the marker byte) and the
/// offset just past it; `None` when `pos` holds no marker.
fn jpeg_marker(bytes: &[u8], pos: usize) -> Option<(u8, usize)> {
    if pos >= bytes.len() || bytes[pos] != 0xFF {
        return None;
    }
    let mut at = pos + 1;
    while at < bytes.len() && bytes[at] == 0xFF {
        at += 1;
    }
    if at >= bytes.len() {
        return None;
    }
    let marker = bytes[at];
    if marker == 0x00 {
        return None;
    }
    Some((marker, at + 1))
}

/// The offset just past the length-prefixed segment body starting at `pos`;
/// `None` when the length fails.
fn jpeg_segment_end(bytes: &[u8], pos: usize) -> Option<usize> {
    if pos + 2 > bytes.len() {
        return None;
    }
    let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    if len < 2 {
        return None;
    }
    let end = pos.checked_add(len)?;
    if end > bytes.len() {
        return None;
    }
    Some(end)
}

/// The offset of the marker ending the scan starting at `pos`: stuffed
/// `0xFF 0x00` pairs and restart markers stay scan data; `None` when no
/// marker ends the scan.
fn jpeg_scan_end(bytes: &[u8], mut pos: usize) -> Option<usize> {
    while pos < bytes.len() {
        if bytes[pos] != 0xFF {
            pos += 1;
            continue;
        }
        if pos + 1 >= bytes.len() {
            return None;
        }
        let next = bytes[pos + 1];
        if next == 0x00 {
            pos += 2;
        } else if next == 0xFF {
            pos += 1;
        } else if matches!(next, 0x01 | 0xD0..=0xD7) {
            pos += 2;
        } else {
            return Some(pos);
        }
    }
    None
}

/// `bytes` as WebP with EXIF, XMP, ICC and unknown chunks removed; `None`
/// when the RIFF structure fails. VP8X metadata flags are cleared while its
/// alpha and animation flags stay, and the RIFF length is recomputed.
/// Trailing data past the last chunk is stripped.
fn scrub_webp(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < 12 || !bytes.starts_with(b"RIFF") || bytes[8..12] != *b"WEBP" {
        return None;
    }
    let riff_len = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
    let end = riff_len.checked_add(8)?;
    if end < 12 || end > bytes.len() {
        return None;
    }
    let mut kept: Vec<([u8; 4], Vec<u8>)> = Vec::new();
    let mut saw_vp8x = false;
    let mut saw_image = false;
    let mut pos: usize = 12;
    while pos.checked_add(8)? <= end {
        let tag = [bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]];
        let size = u32::from_le_bytes([
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]) as usize;
        let data_start = pos + 8;
        let data_end = data_start.checked_add(size)?;
        if data_end > end {
            return None;
        }
        if tag == *b"VP8 " || tag == *b"VP8L" {
            saw_image = true;
            kept.push((tag, bytes[data_start..data_end].to_vec()));
        } else if tag == *b"VP8X" {
            if size != 10 || saw_vp8x {
                return None;
            }
            saw_vp8x = true;
            let mut header = bytes[data_start..data_end].to_vec();
            header[0] &= !(0b0010_0000 | 0b0000_1000 | 0b0000_0100);
            kept.push((tag, header));
        } else if tag == *b"ANMF" {
            kept.push((tag, scrub_webp_frame(&bytes[data_start..data_end])?));
            saw_image = true;
        } else if tag == *b"ALPH" || tag == *b"ANIM" {
            kept.push((tag, bytes[data_start..data_end].to_vec()));
        }
        pos = data_end.checked_add(size & 1)?;
        if pos > end {
            return None;
        }
    }
    if pos != end || !saw_image {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(b"WEBP");
    for (tag, data) in &kept {
        out.extend_from_slice(tag);
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
        if data.len() & 1 == 1 {
            out.push(0);
        }
    }
    let payload = out.len() - 8;
    let Ok(riff_len) = u32::try_from(payload) else {
        return None;
    };
    out[4..8].copy_from_slice(&riff_len.to_le_bytes());
    Some(out)
}

/// A WebP animation frame's image subchunks, with unknown metadata removed.
fn scrub_webp_frame(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut out = bytes.get(..16)?.to_vec();
    let mut pos = 16usize;
    let mut saw_image = false;
    while pos.checked_add(8)? <= bytes.len() {
        let tag = bytes.get(pos..pos + 4)?;
        let len = u32::from_le_bytes(bytes.get(pos + 4..pos + 8)?.try_into().ok()?) as usize;
        let start = pos + 8;
        let end = start.checked_add(len)?;
        let data = bytes.get(start..end)?;
        if tag == b"VP8 " || tag == b"VP8L" || tag == b"ALPH" {
            saw_image |= tag != b"ALPH";
            out.extend_from_slice(tag);
            out.extend_from_slice(&(len as u32).to_le_bytes());
            out.extend_from_slice(data);
            if len & 1 == 1 {
                out.push(0);
            }
        }
        pos = end.checked_add(len & 1)?;
    }
    (pos == bytes.len() && saw_image).then_some(out)
}

/// `bytes` as GIF with application, comment and plain-text extensions
/// removed; `None` when blocks or sub-blocks fail their checks or the
/// trailer never arrives. Image blocks, controls and color tables stay.
/// Trailing data past the trailer is stripped.
fn scrub_gif(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < 13 || (!bytes.starts_with(b"GIF87a") && !bytes.starts_with(b"GIF89a")) {
        return None;
    }
    let mut pos: usize = 13;
    if bytes[10] & 0x80 != 0 {
        let colors = 1usize << ((bytes[10] & 0x07) + 1);
        pos = pos.checked_add(colors.checked_mul(3)?)?;
        if pos > bytes.len() {
            return None;
        }
    }
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[..pos]);
    loop {
        if pos >= bytes.len() {
            return None;
        }
        match bytes[pos] {
            0x3B => {
                out.push(0x3B);
                return Some(out);
            }
            0x21 => {
                if pos + 2 > bytes.len() {
                    return None;
                }
                if bytes[pos + 1] == 0xF9 {
                    if pos + 8 > bytes.len() || bytes[pos + 2] != 0x04 || bytes[pos + 7] != 0x00 {
                        return None;
                    }
                    out.extend_from_slice(&bytes[pos..pos + 8]);
                    pos += 8;
                } else {
                    pos = gif_subblocks_end(bytes, pos + 2)?;
                }
            }
            0x2C => {
                let end = gif_image_end(bytes, pos)?;
                out.extend_from_slice(&bytes[pos..end]);
                pos = end;
            }
            _ => return None,
        }
    }
}

/// The offset just past the sub-block run starting at `pos`; `None` when
/// the run truncates.
fn gif_subblocks_end(bytes: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= bytes.len() {
            return None;
        }
        let size = bytes[pos] as usize;
        pos += 1;
        if size == 0 {
            return Some(pos);
        }
        pos = pos.checked_add(size)?;
        if pos > bytes.len() {
            return None;
        }
    }
}

/// The offset just past the image block opening at `pos`; `None` when its
/// checks fail.
fn gif_image_end(bytes: &[u8], pos: usize) -> Option<usize> {
    if pos + 10 > bytes.len() {
        return None;
    }
    let mut end = pos + 10;
    if bytes[pos + 9] & 0x80 != 0 {
        let colors = 1usize << ((bytes[pos + 9] & 0x07) + 1);
        end = end.checked_add(colors.checked_mul(3)?)?;
        if end > bytes.len() {
            return None;
        }
    }
    if end >= bytes.len() {
        return None;
    }
    gif_subblocks_end(bytes, end + 1)
}
