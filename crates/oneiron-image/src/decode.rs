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

use crate::body::{Format, Icc, MAX_SIDE, bad};

/// What reading a header may allocate (ICC, EXIF and text chunks).
const HEADER_ALLOC: u64 = 16 * 1024 * 1024;
/// The JPEG decoder copies its whole input before it reads a header, so a
/// header read sees this much of it: room for every APPn segment an ICC
/// profile can span.
const JPEG_HEADER_PREFIX: usize = 17 * 1024 * 1024;

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

/// The colour space the file declares, as far as the organ cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Profile {
    Untagged,
    /// An ICC profile whose colorants and curves are sRGB's, or a PNG
    /// `sRGB` or sRGB `cICP` chunk.
    Srgb,
    /// Anything else, named by its description or the chunk that says it.
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
                "the colour space {name:?} is not sRGB; only sRGB or untagged images open"
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
/// truncated header, `too_large` for metadata past the header allowance.
pub fn read_header(bytes: &[u8]) -> Result<Header, OrganError> {
    let format = sniff(bytes)?;
    match format {
        Format::Png => {
            let chunks = png_colour(bytes)?;
            let decoder = PngDecoder::with_limits(Cursor::new(bytes), header_limits())
                .map_err(image_error)?;
            let animated = decoder.is_apng().map_err(image_error)?;
            header_of(decoder, format, animated, Some(&chunks))
        }
        Format::Jpeg => {
            let prefix = &bytes[..bytes.len().min(JPEG_HEADER_PREFIX)];
            let mut decoder = JpegDecoder::new(Cursor::new(prefix)).map_err(image_error)?;
            decoder.set_limits(header_limits()).map_err(image_error)?;
            header_of(decoder, format, false, None)
        }
        Format::Webp => {
            // The WebP decoder takes no allocation limit for its metadata,
            // and trusts the frame's own size over the canvas: check both
            // here, before it reads anything.
            let frame = webp_frame(bytes)?;
            let decoder = WebPDecoder::new(Cursor::new(bytes)).map_err(image_error)?;
            let animated = decoder.has_animation();
            if !animated && frame.is_some_and(|frame| frame != decoder.dimensions()) {
                return Err(bad("the WebP frame does not match its canvas"));
            }
            header_of(decoder, format, animated, None)
        }
    }
}

fn header_of(
    mut decoder: impl ImageDecoder,
    format: Format,
    animated: bool,
    png: Option<&PngColour>,
) -> Result<Header, OrganError> {
    let (stored_width, stored_height) = decoder.dimensions();
    // PNG, JPEG and WebP report the colour type they decode to: a paletted or
    // low-bit PNG expands to eight bits, a 16-bit one stays 16.
    let color = decoder.color_type();
    let channels = color.channel_count();
    let depth =
        u8::try_from(color.bits_per_pixel() / u16::from(channels.max(1))).unwrap_or(u8::MAX);
    let icc = decoder.icc_profile().map_err(image_error)?;
    let profile = match png {
        Some(chunks) => chunks.profile(icc.as_deref()),
        None => icc.as_deref().map_or(Profile::Untagged, classify_icc),
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

/// sRGB only if the profile's colorants and tone curves are sRGB's. Its
/// description names it in a refusal, and proves nothing.
fn classify_icc(icc: &[u8]) -> Profile {
    if icc_is_srgb(icc) {
        return Profile::Srgb;
    }
    let name = icc_description(icc).unwrap_or_default();
    Profile::Other(if name.is_empty() {
        "an unnamed ICC profile".into()
    } else {
        name
    })
}

/// sRGB's colorants, adapted to D50 as an ICC profile stores them.
const SRGB_COLORANTS: [(&[u8; 4], [f64; 3]); 3] = [
    (b"rXYZ", [0.436_075, 0.222_504, 0.013_932]),
    (b"gXYZ", [0.385_065, 0.716_879, 0.097_105]),
    (b"bXYZ", [0.143_080, 0.060_617, 0.714_173]),
];
/// How far a profile's colorant may sit from sRGB's (profiles round them).
const COLORANT_SLACK: f64 = 0.003;

fn icc_is_srgb(icc: &[u8]) -> bool {
    let rgb = icc.get(16..20) == Some(b"RGB ".as_slice());
    let xyz = icc.get(20..24) == Some(b"XYZ ".as_slice());
    rgb && xyz
        && SRGB_COLORANTS.iter().all(|(tag, want)| {
            icc_tag(icc, tag).and_then(xyz_of).is_some_and(|got| {
                got.iter()
                    .zip(want)
                    .all(|(got, want)| (got - want).abs() <= COLORANT_SLACK)
            })
        })
        && [b"rTRC", b"gTRC", b"bTRC"]
            .iter()
            .all(|tag| icc_tag(icc, tag).is_some_and(curve_is_srgb))
}

/// One tag's bytes, by its signature.
fn icc_tag<'a>(icc: &'a [u8], signature: &[u8; 4]) -> Option<&'a [u8]> {
    let count = be32(icc, 128)?.min(256);
    (0..count).find_map(|i| {
        let entry = 132 + i * 12;
        if icc.get(entry..entry + 4)? != signature {
            return None;
        }
        let (offset, size) = (be32(icc, entry + 4)?, be32(icc, entry + 8)?);
        icc.get(offset..offset.checked_add(size)?)
    })
}

fn s15f16(bytes: &[u8], at: usize) -> Option<f64> {
    let word: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(f64::from(i32::from_be_bytes(word)) / 65_536.0)
}

fn xyz_of(tag: &[u8]) -> Option<[f64; 3]> {
    if tag.get(0..4)? != b"XYZ " {
        return None;
    }
    Some([s15f16(tag, 8)?, s15f16(tag, 12)?, s15f16(tag, 16)?])
}

/// The sRGB transfer function, encoded value to linear light.
fn srgb_to_linear(v: f64) -> f64 {
    if v <= 0.040_45 {
        v / 12.92
    } else {
        ((v + 0.055) / 1.055).powf(2.4)
    }
}

/// A `para` curve with sRGB's parameters, or a `curv` table that follows
/// sRGB's curve within one percent at nine points. A bare gamma is not sRGB.
fn curve_is_srgb(tag: &[u8]) -> bool {
    match tag.get(0..4) {
        Some(b"para") => {
            let kind = tag.get(8..10).map(|k| u16::from_be_bytes([k[0], k[1]]));
            let params: Option<Vec<f64>> = (0..5).map(|i| s15f16(tag, 12 + i * 4)).collect();
            let want = [2.4, 1.0 / 1.055, 0.055 / 1.055, 1.0 / 12.92, 0.040_45];
            matches!(kind, Some(3 | 4))
                && params.is_some_and(|got| {
                    got.iter()
                        .zip(want)
                        .all(|(got, want)| (got - want).abs() <= 0.002 + want * 0.002)
                })
        }
        Some(b"curv") => {
            let Some(count) = be32(tag, 8).filter(|count| *count >= 2) else {
                return false;
            };
            (0..=8).all(|step| {
                let i = (count - 1) * step / 8;
                let Some(entry) = tag.get(12 + i * 2..14 + i * 2) else {
                    return false;
                };
                let got = f64::from(u16::from_be_bytes([entry[0], entry[1]])) / 65_535.0;
                let want = srgb_to_linear(i as f64 / (count - 1) as f64);
                (got - want).abs() <= 0.01
            })
        }
        _ => false,
    }
}

/// The colour chunks a PNG carries before its pixels.
#[derive(Debug, Default)]
pub(crate) struct PngColour {
    srgb: bool,
    iccp: bool,
    /// `gAMA`: the file gamma times 100,000 (sRGB is about 45,455).
    gamma: Option<usize>,
    /// `cHRM`: white, red, green and blue x and y, times 100,000.
    chromaticities: Option<[usize; 8]>,
    /// `cICP`: primaries, transfer, matrix, full range.
    cicp: Option<[u8; 4]>,
}

/// sRGB's white point and primaries, times 100,000.
const SRGB_CHROMATICITIES: [usize; 8] = [
    31_270, 32_900, 64_000, 33_000, 30_000, 60_000, 15_000, 6_000,
];

impl PngColour {
    /// The colour space, by PNG's precedence: `cICP`, then `iCCP`, then
    /// `sRGB`, then `gAMA` and `cHRM`. Only a file with none of them is
    /// untagged.
    fn profile(&self, icc: Option<&[u8]>) -> Profile {
        if let Some([primaries, transfer, matrix, full]) = self.cicp {
            return if [primaries, transfer, matrix, full] == [1, 13, 0, 1] {
                Profile::Srgb
            } else {
                Profile::Other(format!("cICP {primaries}/{transfer}/{matrix}/{full}"))
            };
        }
        if let Some(icc) = icc {
            return classify_icc(icc);
        }
        if self.iccp {
            return Profile::Other("an unreadable ICC profile".into());
        }
        if self.srgb {
            return Profile::Srgb;
        }
        if let Some(gamma) = self.gamma
            && !(44_000..=47_000).contains(&gamma)
        {
            return Profile::Other(format!("gamma {:.2}", 100_000.0 / gamma.max(1) as f64));
        }
        if let Some(chromaticities) = self.chromaticities
            && chromaticities
                .iter()
                .zip(SRGB_CHROMATICITIES)
                .any(|(got, want)| got.abs_diff(want) > 1_000)
        {
            return Profile::Other("cHRM primaries that are not sRGB's".into());
        }
        Profile::Untagged
    }
}

/// Walks a PNG's chunks up to its first pixels.
///
/// # Errors
/// `bad_request` for a chunk that runs past the file.
pub(crate) fn png_colour(bytes: &[u8]) -> Result<PngColour, OrganError> {
    let cut = || bad("the PNG is cut short");
    let mut colour = PngColour::default();
    let mut at = 8usize;
    loop {
        let len = be32(bytes, at).ok_or_else(cut)?;
        let kind = bytes.get(at + 4..at + 8).ok_or_else(cut)?;
        // The pixels may be cut short: that is the decoder's to find.
        if kind == b"IDAT" || kind == b"IEND" {
            return Ok(colour);
        }
        let start = at + 8;
        let data = start
            .checked_add(len)
            .and_then(|stop| bytes.get(start..stop))
            .ok_or_else(cut)?;
        match kind {
            b"sRGB" => colour.srgb = true,
            b"iCCP" => colour.iccp = true,
            b"gAMA" => colour.gamma = be32(data, 0),
            b"cHRM" => {
                colour.chromaticities = (0..8)
                    .map(|i| be32(data, i * 4))
                    .collect::<Option<Vec<_>>>()
                    .and_then(|values| values.try_into().ok());
            }
            b"cICP" => colour.cicp = data.get(0..4).and_then(|code| code.try_into().ok()),
            _ => {}
        }
        at = start
            .checked_add(len)
            .and_then(|end| end.checked_add(4))
            .ok_or_else(cut)?;
    }
}

fn le32(bytes: &[u8], at: usize) -> Option<usize> {
    let word: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    usize::try_from(u32::from_le_bytes(word)).ok()
}

fn le24(bytes: &[u8], at: usize) -> Option<u32> {
    let [a, b, c]: [u8; 3] = bytes.get(at..at.checked_add(3)?)?.try_into().ok()?;
    Some(u32::from_le_bytes([a, b, c, 0]))
}

/// A lossy frame's size, from its key frame header.
fn vp8_size(data: &[u8]) -> Option<(u32, u32)> {
    let key_frame = data.first()? & 1 == 0;
    if !key_frame || data.get(3..6)? != [0x9d, 0x01, 0x2a] {
        return None;
    }
    let w = u32::from(u16::from_le_bytes([*data.get(6)?, *data.get(7)?]) & 0x3fff);
    let h = u32::from(u16::from_le_bytes([*data.get(8)?, *data.get(9)?]) & 0x3fff);
    Some((w, h))
}

/// A lossless frame's size, from its header.
fn vp8l_size(data: &[u8]) -> Option<(u32, u32)> {
    if *data.first()? != 0x2f {
        return None;
    }
    let bits = u32::from_le_bytes(data.get(1..5)?.try_into().ok()?);
    Some(((bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1))
}

/// Checks a WebP's chunks before any decoder sees them: each chunk fits the
/// file and metadata fits the header allowance. Returns a still image's
/// frame size, which must match the canvas.
///
/// # Errors
/// `bad_request` for a cut-short file or frame header, `too_large` for
/// metadata past the allowance.
fn webp_frame(bytes: &[u8]) -> Result<Option<(u32, u32)>, OrganError> {
    let cut = || bad("the WebP is cut short");
    let end = le32(bytes, 4)
        .and_then(|riff| riff.checked_add(8))
        .filter(|end| *end <= bytes.len())
        .ok_or_else(cut)?;
    let mut frame = None;
    let mut at = 12;
    while at < end {
        let kind = bytes.get(at..at + 4).ok_or_else(cut)?;
        let len = le32(bytes, at + 4).ok_or_else(cut)?;
        let start = at + 8;
        let stop = start
            .checked_add(len)
            .filter(|stop| *stop <= end)
            .ok_or_else(cut)?;
        let data = &bytes[start..stop];
        match kind {
            b"ICCP" | b"EXIF" | b"XMP " if len as u64 > HEADER_ALLOC => {
                return Err(OrganError::new(
                    ErrorCode::TooLarge,
                    format!("a WebP metadata chunk of {len} bytes is past {HEADER_ALLOC}"),
                ));
            }
            b"VP8 " => frame = Some(vp8_size(data).ok_or_else(|| bad("a bad VP8 frame header"))?),
            b"VP8L" => {
                frame = Some(vp8l_size(data).ok_or_else(|| bad("a bad VP8L frame header"))?);
            }
            _ => {}
        }
        at = stop + (len & 1);
    }
    Ok(frame)
}

fn be32(bytes: &[u8], at: usize) -> Option<usize> {
    let word: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    usize::try_from(u32::from_be_bytes(word)).ok()
}

/// The profile's `desc` tag text: ICC v2 `desc` (ASCII) or v4 `mluc`
/// (UTF-16BE, first record).
fn icc_description(icc: &[u8]) -> Option<String> {
    let tag = icc_tag(icc, b"desc")?;
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
    // The JPEG decoder copies its whole input first.
    if header.format == Format::Jpeg && bytes.len() as u64 > max_bytes {
        return Err(OrganError::new(
            ErrorCode::TooLarge,
            format!("a {}-byte JPEG is past {max_bytes}", bytes.len()),
        ));
    }
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
