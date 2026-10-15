//! Asset admission: the binding, provenance and stored bytes, checked before
//! any byte is interpreted; and raster sniffing for image bindings.

use super::{EMU_PER_PX, Extent, GraphicError, GraphicInput, GraphicLimits, Origin};
use crate::design_plan::{AssetKind, MediaType};

const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

/// The stored bytes of an asset whose record may be used as the plan asks.
pub(super) fn admit<'a>(input: &GraphicInput<'a>) -> Result<&'a [u8], GraphicError> {
    let record = input.record;
    if input.binding.handle != record.artifact || input.binding.media != record.media {
        return Err(GraphicError::BindingMismatch);
    }
    if input.bounds.cx <= 0 || input.bounds.cy <= 0 {
        return Err(GraphicError::EmptyBounds);
    }
    if record.description.trim().is_empty() {
        return Err(GraphicError::MissingDescription);
    }
    if record
        .provenance
        .iter()
        .all(|reference| reference.trim().is_empty())
    {
        return Err(GraphicError::MissingProvenance);
    }
    match &record.origin {
        Origin::Web | Origin::Stock
            if record
                .rights
                .iter()
                .all(|reference| reference.trim().is_empty()) =>
        {
            return Err(GraphicError::MissingLicence);
        }
        _ => {}
    }
    if input.requested == AssetKind::Factual
        && matches!(record.origin, Origin::Stock | Origin::Generated { .. })
    {
        return Err(GraphicError::NotFactual);
    }
    if let Origin::Generated { reviewed, receipt } = &record.origin {
        let prompt = receipt
            .prompt
            .ok_or(GraphicError::AdapterProvenance("prompt"))?;
        let references = receipt
            .references
            .as_ref()
            .ok_or(GraphicError::AdapterProvenance("references"))?;
        for (field, value) in [("model", &receipt.model), ("adapter", &receipt.adapter)] {
            if value.as_deref().is_none_or(|value| value.trim().is_empty()) {
                return Err(GraphicError::AdapterProvenance(field));
            }
        }
        receipt
            .params_hash
            .ok_or(GraphicError::AdapterProvenance("params_hash"))?;
        let output = receipt
            .output_hash
            .ok_or(GraphicError::AdapterProvenance("output_hash"))?;
        if prompt != reviewed.prompt || *references != reviewed.references {
            return Err(GraphicError::ReviewDrift);
        }
        if output != record.content_hash {
            return Err(GraphicError::OutputHash);
        }
    }
    let bytes = input.bytes.ok_or(GraphicError::MissingBytes)?;
    let ceiling = match record.media {
        MediaType::Svg => input.limits.svg_bytes,
        MediaType::Png | MediaType::Jpeg => input.limits.raster_bytes,
    };
    if bytes.len() > ceiling {
        return Err(GraphicError::ResourceLimit);
    }
    if *blake3::hash(bytes).as_bytes() != record.content_hash {
        return Err(GraphicError::HashMismatch);
    }
    Ok(bytes)
}

/// The pixel size a PNG or JPEG declares, at 1px = 9,525 EMU.
pub(super) fn raster_extent(
    media: MediaType,
    bytes: &[u8],
    limits: &GraphicLimits,
) -> Result<Extent, GraphicError> {
    let (width, height) = match media {
        MediaType::Png => png_size(bytes),
        MediaType::Jpeg => jpeg_size(bytes),
        MediaType::Svg => None,
    }
    .filter(|&(width, height)| width > 0 && height > 0)
    .ok_or(GraphicError::UnsupportedPayload)?;
    if u64::from(width) * u64::from(height) > limits.raster_pixels {
        return Err(GraphicError::ResourceLimit);
    }
    Ok(Extent {
        cx: i64::from(width) * EMU_PER_PX,
        cy: i64::from(height) * EMU_PER_PX,
    })
}

/// The IHDR size, which the PNG format puts first.
fn png_size(bytes: &[u8]) -> Option<(u32, u32)> {
    if !bytes.starts_with(PNG_SIGNATURE) || bytes.get(12..16)? != b"IHDR" {
        return None;
    }
    Some((be32(bytes.get(16..20)?)?, be32(bytes.get(20..24)?)?))
}

/// The size in the first start-of-frame segment, read marker by marker.
fn jpeg_size(bytes: &[u8]) -> Option<(u32, u32)> {
    if !bytes.starts_with(&[0xFF, 0xD8]) {
        return None;
    }
    let mut at = 2;
    loop {
        if *bytes.get(at)? != 0xFF {
            return None;
        }
        while *bytes.get(at)? == 0xFF {
            at += 1;
        }
        let marker = *bytes.get(at)?;
        at += 1;
        if matches!(marker, 0x01 | 0xD0..=0xD7) {
            continue;
        }
        if matches!(marker, 0xD8..=0xDA) {
            return None;
        }
        let length = usize::from(be16(bytes.get(at..at + 2)?)?);
        if length < 2 {
            return None;
        }
        if matches!(marker, 0xC0..=0xCF) && !matches!(marker, 0xC4 | 0xC8 | 0xCC) {
            let height = be16(bytes.get(at + 3..at + 5)?)?;
            let width = be16(bytes.get(at + 5..at + 7)?)?;
            return Some((u32::from(width), u32::from(height)));
        }
        at += length;
    }
}

fn be32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

fn be16(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.try_into().ok()?))
}
