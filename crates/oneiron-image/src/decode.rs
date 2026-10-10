//! Reading an image: the header first, then pixels only when it passes.
//!
//! The first promise is a single frame, eight bits a channel, in sRGB. The
//! header says everything needed to keep it: format, size, depth, alpha,
//! colour profile, EXIF orientation and animation. A source that breaks the
//! promise is refused before any pixel buffer exists.

use std::io::Cursor;

use image::codecs::jpeg::JpegDecoder;
use image::codecs::png::PngDecoder;
use image::codecs::webp::WebPDecoder;
use image::metadata::Orientation;
use image::{ColorType, DynamicImage, ImageDecoder, ImageError, ImageFormat, Limits, RgbaImage};
use oneiron_organ_protocol::{ErrorCode, OrganError};

use crate::body::{Format, Icc, bad};

/// The longest side the organ opens.
pub const MAX_SIDE: u32 = 65_535;
/// What reading a header may allocate (ICC, EXIF and text chunks).
const HEADER_ALLOC: u64 = 16 * 1024 * 1024;

/// What a header says, before any pixels are read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub format: Format,
    /// The stored size, before orientation.
    pub stored_width: u32,
    pub stored_height: u32,
    /// EXIF orientation, 1 to 8 (1 when absent).
    pub orientation: u8,
    /// Bits per channel as decoded.
    pub depth: u8,
    pub channels: u8,
    pub alpha: bool,
    pub profile: Profile,
    pub animated: bool,
}

/// The ICC profile, as far as the organ cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Profile {
    Untagged,
    Srgb,
    /// Any other profile, by its description.
    Other(String),
}

impl Header {
    /// The size after orientation.
    #[must_use]
    pub fn size(&self) -> (u32, u32) {
        if matches!(self.orientation, 5..=8) {
            (self.stored_height, self.stored_width)
        } else {
            (self.stored_width, self.stored_height)
        }
    }

    /// Bytes of the decoded, oriented RGBA.
    #[must_use]
    pub fn rgba_bytes(&self) -> u64 {
        u64::from(self.stored_width) * u64::from(self.stored_height) * 4
    }

    /// Why the first slice cannot keep this image, if it cannot.
    #[must_use]
    pub fn refusal(&self) -> Option<String> {
        if self.animated {
            return Some("animated images are not supported".into());
        }
        if self.depth != 8 {
            return Some(format!(
                "{}-bit channels are not supported; the first slice is 8-bit",
                self.depth
            ));
        }
        if let Profile::Other(name) = &self.profile {
            return Some(format!(
                "the ICC profile {name:?} is not sRGB; only sRGB or untagged images open"
            ));
        }
        None
    }

    /// The profile as the body records it; `None` if it is not sRGB.
    #[must_use]
    pub fn icc(&self) -> Option<Icc> {
        match self.profile {
            Profile::Untagged => Some(Icc::None),
            Profile::Srgb => Some(Icc::Srgb),
            Profile::Other(_) => None,
        }
    }
}

fn image_error(err: ImageError) -> OrganError {
    match err {
        ImageError::Limits(limit) => OrganError::new(ErrorCode::TooLarge, limit.to_string()),
        ImageError::Unsupported(unsupported) => {
            OrganError::new(ErrorCode::Unsupported, unsupported.to_string())
        }
        other => bad(format!("the image is corrupt: {other}")),
    }
}

/// The format by its magic bytes, whatever the media type claims.
///
/// # Errors
/// `unsupported` for anything but PNG, JPEG or WebP.
pub(crate) fn sniff(bytes: &[u8]) -> Result<Format, OrganError> {
    match image::guess_format(bytes) {
        Ok(ImageFormat::Png) => Ok(Format::Png),
        Ok(ImageFormat::Jpeg) => Ok(Format::Jpeg),
        Ok(ImageFormat::WebP) => Ok(Format::Webp),
        _ => Err(OrganError::new(
            ErrorCode::Unsupported,
            "not a PNG, JPEG or WebP image",
        )),
    }
}

fn header_limits() -> Limits {
    let mut limits = Limits::no_limits();
    limits.max_alloc = Some(HEADER_ALLOC);
    limits
}

/// Reads the header only.
///
/// # Errors
/// `unsupported` for another format, `bad_request` for a corrupt or
/// truncated header.
pub fn read_header(bytes: &[u8]) -> Result<Header, OrganError> {
    let format = sniff(bytes)?;
    let cursor = Cursor::new(bytes);
    match format {
        Format::Png => {
            let decoder = PngDecoder::with_limits(cursor, header_limits()).map_err(image_error)?;
            let animated = decoder.is_apng().map_err(image_error)?;
            header_of(decoder, format, animated)
        }
        Format::Jpeg => {
            let mut decoder = JpegDecoder::new(cursor).map_err(image_error)?;
            decoder.set_limits(header_limits()).map_err(image_error)?;
            header_of(decoder, format, false)
        }
        Format::Webp => {
            let mut decoder = WebPDecoder::new(cursor).map_err(image_error)?;
            decoder.set_limits(header_limits()).map_err(image_error)?;
            let animated = decoder.has_animation();
            header_of(decoder, format, animated)
        }
    }
}

fn header_of(
    mut decoder: impl ImageDecoder,
    format: Format,
    animated: bool,
) -> Result<Header, OrganError> {
    let (stored_width, stored_height) = decoder.dimensions();
    // PNG, JPEG and WebP report the colour type they decode to: a paletted or
    // low-bit PNG expands to eight bits, a 16-bit one stays 16.
    let color = decoder.color_type();
    let channels = color.channel_count();
    let depth =
        u8::try_from(color.bits_per_pixel() / u16::from(channels.max(1))).unwrap_or(u8::MAX);
    let profile = match decoder.icc_profile().map_err(image_error)? {
        None => Profile::Untagged,
        Some(icc) => classify_icc(&icc),
    };
    let orientation = decoder.orientation().map_err(image_error)?.to_exif();
    Ok(Header {
        format,
        stored_width,
        stored_height,
        orientation,
        depth,
        channels,
        alpha: color.has_alpha(),
        profile,
        animated,
    })
}

/// sRGB if the profile is RGB and its description names sRGB.
fn classify_icc(icc: &[u8]) -> Profile {
    let name = icc_description(icc).unwrap_or_default();
    let rgb = icc.get(16..20) == Some(b"RGB ".as_slice());
    if rgb && name.to_ascii_lowercase().contains("srgb") {
        Profile::Srgb
    } else if name.is_empty() {
        Profile::Other("unnamed".into())
    } else {
        Profile::Other(name)
    }
}

fn be32(bytes: &[u8], at: usize) -> Option<usize> {
    let word: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    usize::try_from(u32::from_be_bytes(word)).ok()
}

/// The profile's `desc` tag text: ICC v2 `desc` (ASCII) or v4 `mluc`
/// (UTF-16BE, first record).
fn icc_description(icc: &[u8]) -> Option<String> {
    let count = be32(icc, 128)?.min(256);
    let (offset, size) = (0..count).find_map(|i| {
        let entry = 132 + i * 12;
        (icc.get(entry..entry + 4)? == b"desc")
            .then_some((be32(icc, entry + 4)?, be32(icc, entry + 8)?))
    })?;
    let tag = icc.get(offset..offset.checked_add(size)?)?;
    match tag.get(0..4)? {
        b"desc" => {
            let len = be32(tag, 8)?;
            let text = tag.get(12..12usize.checked_add(len)?)?;
            Some(
                String::from_utf8_lossy(text)
                    .trim_end_matches('\0')
                    .to_owned(),
            )
        }
        b"mluc" => {
            let len = be32(tag, 20)?;
            let at = be32(tag, 24)?;
            let text = tag.get(at..at.checked_add(len)?)?;
            let units: Vec<u16> = text
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect();
            Some(
                String::from_utf16_lossy(&units)
                    .trim_end_matches('\0')
                    .to_owned(),
            )
        }
        _ => None,
    }
}

/// Decodes one frame to oriented RGBA, inside `max_bytes`.
///
/// # Errors
/// `too_large` past the limits, `bad_request` for corrupt data.
pub(crate) fn decode(
    bytes: &[u8],
    header: &Header,
    max_bytes: u64,
) -> Result<RgbaImage, OrganError> {
    check_size(header, max_bytes)?;
    let mut limits = Limits::no_limits();
    limits.max_image_width = Some(MAX_SIDE);
    limits.max_image_height = Some(MAX_SIDE);
    limits.max_alloc = Some(max_bytes);
    let cursor = Cursor::new(bytes);
    let orientation =
        Orientation::from_exif(header.orientation).unwrap_or(Orientation::NoTransforms);
    let image = match header.format {
        Format::Png => {
            let decoder = PngDecoder::with_limits(cursor, limits).map_err(image_error)?;
            pixels(decoder, None)
        }
        Format::Jpeg => pixels(JpegDecoder::new(cursor).map_err(image_error)?, Some(limits)),
        Format::Webp => pixels(WebPDecoder::new(cursor).map_err(image_error)?, Some(limits)),
    }?;
    let mut image = image;
    image.apply_orientation(orientation);
    Ok(image.into_rgba8())
}

fn pixels(
    mut decoder: impl ImageDecoder,
    limits: Option<Limits>,
) -> Result<DynamicImage, OrganError> {
    if let Some(limits) = limits {
        decoder.set_limits(limits).map_err(image_error)?;
    }
    if !matches!(
        decoder.color_type(),
        ColorType::L8 | ColorType::La8 | ColorType::Rgb8 | ColorType::Rgba8
    ) {
        return Err(OrganError::new(
            ErrorCode::Unsupported,
            "only 8-bit channels are supported",
        ));
    }
    DynamicImage::from_decoder(decoder).map_err(image_error)
}

/// Refuses an image too large to hold, from its header alone.
///
/// # Errors
/// `too_large`.
pub(crate) fn check_size(header: &Header, max_bytes: u64) -> Result<(), OrganError> {
    let (w, h) = (header.stored_width, header.stored_height);
    if w == 0 || h == 0 {
        return Err(bad("the image has no pixels"));
    }
    if w > MAX_SIDE || h > MAX_SIDE || header.rgba_bytes() > max_bytes {
        return Err(OrganError::new(
            ErrorCode::TooLarge,
            format!(
                "{w}x{h} needs {} bytes decoded; this organ holds {max_bytes}",
                header.rgba_bytes()
            ),
        ));
    }
    Ok(())
}
