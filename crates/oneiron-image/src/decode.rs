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
            let header = JpegDecoder::new(Cursor::new(prefix))
                .and_then(|mut decoder| {
                    decoder.set_limits(header_limits())?;
                    Ok(decoder)
                })
                .map_err(image_error)
                .and_then(|decoder| header_of(decoder, format, false, None));
            match header {
                // The prefix ended before the header did: refused as too
                // large, not called corrupt.
                Err(err) if err.code == ErrorCode::BadRequest && bytes.len() > prefix.len() => {
                    Err(OrganError::new(
                        ErrorCode::TooLarge,
                        format!("the JPEG's header runs past {JPEG_HEADER_PREFIX} bytes"),
                    ))
                }
                header => header,
            }
        }
        Format::Webp => {
            // The WebP decoder takes no allocation limit for its metadata,
            // reads past the declared end, keeps the first of repeated
            // chunks and trusts the frame's own size over the canvas: the
            // walk checks all of it before the decoder reads anything.
            match webp_chunks(bytes)? {
                Webp::Animated { canvas, alpha } => Ok(Header {
                    format,
                    stored_width: canvas.0,
                    stored_height: canvas.1,
                    orientation: 1,
                    depth: 8,
                    channels: if alpha { 4 } else { 3 },
                    alpha,
                    profile: Profile::Untagged,
                    animated: true,
                }),
                Webp::Still {
                    riff,
                    frame,
                    orientation,
                    ..
                } => {
                    let decoder = WebPDecoder::new(Cursor::new(riff)).map_err(image_error)?;
                    if frame != decoder.dimensions() {
                        return Err(bad("the WebP frame does not match its canvas"));
                    }
                    let mut header = header_of(decoder, format, false, None)?;
                    header.orientation = orientation;
                    Ok(header)
                }
            }
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
    let Some(icc) = icc_whole(icc) else {
        return false;
    };
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

/// The profile as its header sizes it, if the whole tag table and every tag
/// it lists lie inside.
fn icc_whole(icc: &[u8]) -> Option<&[u8]> {
    let icc = icc.get(..be32(icc, 0)?)?;
    let count = be32(icc, 128)?;
    let table_end = count.checked_mul(12)?.checked_add(132)?;
    if table_end > icc.len() {
        return None;
    }
    (0..count)
        .all(|i| {
            let entry = 132 + i * 12;
            be32(icc, entry + 4)
                .zip(be32(icc, entry + 8))
                .and_then(|(offset, size)| offset.checked_add(size))
                .is_some_and(|end| end <= icc.len())
        })
        .then_some(icc)
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

/// A table curve needs this many entries for straight lines between them
/// to stay on sRGB's curve.
const MIN_CURVE_ENTRIES: usize = 16;

/// A `para` curve of sRGB's form with sRGB's parameters, every one of them;
/// or a `curv` table of at least [`MIN_CURVE_ENTRIES`] whose every entry is
/// within one percent of sRGB's curve. A bare gamma is not sRGB.
fn curve_is_srgb(tag: &[u8]) -> bool {
    match tag.get(0..4) {
        Some(b"para") => {
            // Type 3 is sRGB's form; type 4 adds two offsets, which must be zero.
            let (count, want): (usize, &[f64]) =
                match tag.get(8..10).map(|k| u16::from_be_bytes([k[0], k[1]])) {
                    Some(3) => (5, &SRGB_PARAMETERS[..5]),
                    Some(4) => (7, &SRGB_PARAMETERS),
                    _ => return false,
                };
            (0..count).all(|i| {
                s15f16(tag, 12 + i * 4)
                    .is_some_and(|got| (got - want[i]).abs() <= 0.002 + want[i] * 0.002)
            })
        }
        Some(b"curv") => {
            let Some(count) = be32(tag, 8).filter(|count| *count >= MIN_CURVE_ENTRIES) else {
                return false;
            };
            let Some(entries) = count.checked_mul(2).and_then(|len| tag.get(12..12 + len)) else {
                return false;
            };
            entries.chunks_exact(2).enumerate().all(|(i, entry)| {
                let got = f64::from(u16::from_be_bytes([entry[0], entry[1]])) / 65_535.0;
                let want = srgb_to_linear(i as f64 / (count - 1) as f64);
                (got - want).abs() <= 0.01
            })
        }
        _ => false,
    }
}

/// sRGB's curve as an ICC parametric curve: g, a, b, c, d, then e and f.
const SRGB_PARAMETERS: [f64; 7] = [
    2.4,
    1.0 / 1.055,
    0.055 / 1.055,
    1.0 / 12.92,
    0.040_45,
    0.0,
    0.0,
];

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
    let mut seen = std::collections::BTreeSet::new();
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
        let colour_chunk = matches!(kind, b"sRGB" | b"iCCP" | b"gAMA" | b"cHRM" | b"cICP");
        if colour_chunk {
            // The decoder skips a colour chunk it finds malformed and keeps
            // the next one down; this walk would not. Refuse the file
            // rather than disagree with it about its colour.
            let crc = be32(bytes, start + len).ok_or_else(cut)?;
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(kind);
            hasher.update(data);
            let exact = match kind {
                b"sRGB" => len == 1 && data[0] <= 3,
                b"gAMA" | b"cICP" => len == 4,
                b"cHRM" => len == 32,
                _ => len >= 3,
            };
            if !exact || hasher.finalize() as usize != crc || !seen.insert(kind) {
                let name = String::from_utf8_lossy(kind);
                return Err(bad(format!("a malformed or repeated {name} chunk")));
            }
        }
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

/// A lossless frame's size and its alpha hint, from its header.
fn vp8l_header(data: &[u8]) -> Option<((u32, u32), bool)> {
    if *data.first()? != 0x2f {
        return None;
    }
    let bits = u32::from_le_bytes(data.get(1..5)?.try_into().ok()?);
    Some((
        ((bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1),
        bits & (1 << 28) != 0,
    ))
}

/// A WebP as its chunks say, checked before any decoder sees it.
enum Webp<'a> {
    /// One frame. `riff` is the file up to its declared end: the decoder
    /// sees nothing past it.
    Still {
        riff: &'a [u8],
        frame: (u32, u32),
        /// EXIF orientation, 1 when absent.
        orientation: u8,
        /// Bytes whose 0x10 bit, set, makes the decoder keep transparency
        /// the header calls absent (a lossless frame's alpha hint, the
        /// extended header's alpha flag): offsets into `riff`.
        alpha_bits: Vec<usize>,
    },
    /// Refused unread: its frames hold chunks of their own.
    Animated { canvas: (u32, u32), alpha: bool },
}

/// Walks a WebP's top-level chunks: each must fit the declared RIFF, its
/// metadata must fit the header allowance, a still image has exactly one
/// frame, and an animation is refused before a decoder reads its frames.
///
/// # Errors
/// `bad_request` for a cut-short file, a bad or repeated frame header;
/// `too_large` for metadata past the allowance; `unsupported` for a
/// lossless side of 16,384, which the decoder misreads.
fn webp_chunks(bytes: &[u8]) -> Result<Webp<'_>, OrganError> {
    let cut = || bad("the WebP is cut short");
    let end = le32(bytes, 4)
        .and_then(|riff| riff.checked_add(8))
        .filter(|end| *end <= bytes.len())
        .ok_or_else(cut)?;
    let mut frame = None;
    let mut vp8x: Option<(u8, (u32, u32), usize)> = None;
    let (mut lossless_hint, mut alph, mut animation) = (None, false, false);
    let mut orientation = 1;
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
            b"VP8X" => {
                let canvas = (
                    le24(data, 4).ok_or_else(cut)? + 1,
                    le24(data, 7).ok_or_else(cut)? + 1,
                );
                vp8x = Some((*data.first().ok_or_else(cut)?, canvas, start));
            }
            b"ANIM" | b"ANMF" => animation = true,
            b"ALPH" if alph => return Err(bad("a WebP with two alpha chunks")),
            b"ALPH" => alph = true,
            b"VP8 " | b"VP8L" if frame.is_some() => {
                return Err(bad("a still WebP with more than one frame"));
            }
            b"VP8 " => frame = Some(vp8_size(data).ok_or_else(|| bad("a bad VP8 frame header"))?),
            b"VP8L" => {
                let (size, hint) =
                    vp8l_header(data).ok_or_else(|| bad("a bad VP8L frame header"))?;
                if size.0 == 16_384 || size.1 == 16_384 {
                    return Err(OrganError::new(
                        ErrorCode::Unsupported,
                        "a lossless WebP side of 16,384 is not supported yet",
                    ));
                }
                frame = Some(size);
                lossless_hint = Some((hint, start + 4));
            }
            b"EXIF" => orientation = exif_orientation(data),
            _ => {}
        }
        at = stop + (len & 1);
    }
    if let Some((flags, canvas, _)) = vp8x
        && (animation || flags & 0x02 != 0)
    {
        return Ok(Webp::Animated {
            canvas,
            alpha: flags & 0x10 != 0,
        });
    }
    let frame = frame.ok_or_else(|| bad("a WebP with no frame"))?;
    let mut alpha_bits = Vec::new();
    match (vp8x, lossless_hint) {
        // An extended file's alpha flag decides; set it, and the lossless
        // hint, when a frame or chunk may carry alpha the flag denies.
        (Some((flags, _, flags_at)), hint) if flags & 0x10 == 0 && (alph || hint.is_some()) => {
            alpha_bits.push(flags_at);
            alpha_bits.extend(hint.map(|(_, at)| at));
        }
        // A simple lossless file's hint decides.
        (None, Some((false, at))) => alpha_bits.push(at),
        _ => {}
    }
    if animation {
        return Ok(Webp::Animated {
            canvas: frame,
            alpha: true,
        });
    }
    Ok(Webp::Still {
        riff: &bytes[..end],
        frame,
        orientation,
        alpha_bits,
    })
}

fn le24(bytes: &[u8], at: usize) -> Option<u32> {
    let [a, b, c]: [u8; 3] = bytes.get(at..at.checked_add(3)?)?.try_into().ok()?;
    Some(u32::from_le_bytes([a, b, c, 0]))
}

/// An EXIF chunk's orientation, 1 when it has none. WebP writers differ on
/// whether the chunk starts with `Exif\0\0`; both are read.
fn exif_orientation(data: &[u8]) -> u8 {
    let tiff = data.strip_prefix(b"Exif\0\0").unwrap_or(data);
    Orientation::from_exif_chunk(tiff).map_or(1, Orientation::to_exif)
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
        Format::Webp => decode_webp(bytes, limits),
    }?;
    let mut image = image;
    image.apply_orientation(orientation);
    Ok(image.into_rgba8())
}

/// Decodes a still WebP from its checked RIFF. When its header calls alpha
/// absent but a lossless frame or an alpha chunk may still carry it, the
/// decoder would drop it unseen: decode a copy that keeps it, and refuse
/// the file if any pixel is not opaque.
fn decode_webp(bytes: &[u8], limits: Limits) -> Result<DynamicImage, OrganError> {
    let Webp::Still {
        riff, alpha_bits, ..
    } = webp_chunks(bytes)?
    else {
        return Err(OrganError::new(
            ErrorCode::Unsupported,
            "animated images are not supported",
        ));
    };
    if alpha_bits.is_empty() {
        return pixels(
            WebPDecoder::new(Cursor::new(riff)).map_err(image_error)?,
            Some(limits),
        );
    }
    let mut copy = riff.to_vec();
    for at in alpha_bits {
        if let Some(byte) = copy.get_mut(at) {
            *byte |= 0x10;
        }
    }
    let image = pixels(
        WebPDecoder::new(Cursor::new(copy.as_slice())).map_err(image_error)?,
        Some(limits),
    )?;
    drop(copy);
    if image
        .as_rgba8()
        .is_some_and(|rgba| rgba.pixels().any(|px| px.0[3] != u8::MAX))
    {
        return Err(bad(
            "the WebP holds transparency its header says it does not have",
        ));
    }
    Ok(image)
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
