//! Images made in code, so no binary fixture is stored: corner-coded
//! pixels, EXIF and ICC through the encoders, and the few chunk-level
//! shapes (APNG, animated WebP, a lying PNG header) the encoders cannot make.
#![allow(dead_code)]

use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::PngEncoder;
use image::codecs::webp::WebPEncoder;
use image::{ExtendedColorType, ImageEncoder};

/// A pixel that names its own coordinates.
#[must_use]
pub(crate) fn coded(x: u32, y: u32) -> [u8; 4] {
    [
        (x * 9 + 3) as u8,
        (y * 13 + 5) as u8,
        ((x ^ y) * 7) as u8,
        255,
    ]
}

#[must_use]
pub(crate) fn pixels(w: u32, h: u32, f: impl Fn(u32, u32) -> [u8; 4]) -> Vec<u8> {
    let f = &f;
    (0..h)
        .flat_map(|y| (0..w).flat_map(move |x| f(x, y)))
        .collect()
}

/// What to put beside the pixels.
#[derive(Default)]
pub(crate) struct Extra {
    pub(crate) exif: Option<Vec<u8>>,
    pub(crate) icc: Option<Vec<u8>>,
}

#[must_use]
pub(crate) fn png(w: u32, h: u32, rgba: &[u8], extra: Extra) -> Vec<u8> {
    let mut out = Vec::new();
    let mut encoder = PngEncoder::new(&mut out);
    if let Some(exif) = extra.exif {
        encoder.set_exif_metadata(exif).expect("png exif");
    }
    if let Some(icc) = extra.icc {
        encoder.set_icc_profile(icc).expect("png icc");
    }
    encoder
        .write_image(rgba, w, h, ExtendedColorType::Rgba8)
        .expect("png");
    out
}

/// One flat colour, no alpha channel.
#[must_use]
pub(crate) fn png_rgb(w: u32, h: u32, rgb: [u8; 3]) -> Vec<u8> {
    let data: Vec<u8> = (0..w * h).flat_map(|_| rgb).collect();
    let mut out = Vec::new();
    PngEncoder::new(&mut out)
        .write_image(&data, w, h, ExtendedColorType::Rgb8)
        .expect("png rgb");
    out
}

#[must_use]
pub(crate) fn png_rgb16(w: u32, h: u32) -> Vec<u8> {
    let data: Vec<u8> = (0..w * h * 3)
        .flat_map(|i| (i as u16).to_be_bytes())
        .collect();
    let mut out = Vec::new();
    PngEncoder::new(&mut out)
        .write_image(&data, w, h, ExtendedColorType::Rgb16)
        .expect("png16");
    out
}

/// A lossless JPEG does not exist, so JPEG fixtures are one flat colour,
/// which survives the codec within a step or two.
#[must_use]
pub(crate) fn jpeg_flat(w: u32, h: u32, rgb: [u8; 3], exif: Option<Vec<u8>>) -> Vec<u8> {
    let data: Vec<u8> = (0..w * h).flat_map(|_| rgb).collect();
    let mut out = Vec::new();
    let mut encoder = JpegEncoder::new_with_quality(&mut out, 95);
    if let Some(exif) = exif {
        encoder.set_exif_metadata(exif).expect("jpeg exif");
    }
    encoder
        .write_image(&data, w, h, ExtendedColorType::Rgb8)
        .expect("jpeg");
    out
}

#[must_use]
pub(crate) fn webp_lossless(w: u32, h: u32, rgba: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    WebPEncoder::new_lossless(&mut out)
        .write_image(rgba, w, h, ExtendedColorType::Rgba8)
        .expect("webp");
    out
}

/// A big-endian TIFF block holding one tag: Orientation = `value`.
#[must_use]
pub(crate) fn exif_orientation(value: u16) -> Vec<u8> {
    let mut exif = b"MM\0\x2a".to_vec();
    exif.extend(8u32.to_be_bytes());
    exif.extend(1u16.to_be_bytes());
    exif.extend(0x0112u16.to_be_bytes());
    exif.extend(3u16.to_be_bytes());
    exif.extend(1u32.to_be_bytes());
    exif.extend(value.to_be_bytes());
    exif.extend([0, 0]);
    exif.extend(0u32.to_be_bytes());
    exif
}

/// A minimal ICC v2 profile: an RGB header and one `desc` tag naming it.
#[must_use]
pub(crate) fn icc_named(name: &str) -> Vec<u8> {
    let mut desc = b"desc\0\0\0\0".to_vec();
    desc.extend((name.len() as u32 + 1).to_be_bytes());
    desc.extend(name.as_bytes());
    desc.push(0);
    while !desc.len().is_multiple_of(4) {
        desc.push(0);
    }
    let offset = 128 + 4 + 12;
    let total = offset + desc.len();
    let mut icc = vec![0u8; 128];
    icc[0..4].copy_from_slice(&(total as u32).to_be_bytes());
    icc[12..16].copy_from_slice(b"mntr");
    icc[16..20].copy_from_slice(b"RGB ");
    icc[20..24].copy_from_slice(b"XYZ ");
    icc[36..40].copy_from_slice(b"acsp");
    icc.extend(1u32.to_be_bytes());
    icc.extend(b"desc");
    icc.extend((offset as u32).to_be_bytes());
    icc.extend((desc.len() as u32).to_be_bytes());
    icc.extend(desc);
    icc
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut chunk = (data.len() as u32).to_be_bytes().to_vec();
    let mut body = kind.to_vec();
    body.extend(data);
    chunk.extend(&body);
    chunk.extend(crc32(&body).to_be_bytes());
    chunk
}

/// Byte offset just past the IHDR chunk (signature 8 + IHDR 25).
const AFTER_IHDR: usize = 33;

/// The PNG with its IHDR saying `w x h`, whatever the data holds.
#[must_use]
pub(crate) fn png_lying_size(png: &[u8], w: u32, h: u32) -> Vec<u8> {
    let mut ihdr = png[16..29].to_vec();
    ihdr[0..4].copy_from_slice(&w.to_be_bytes());
    ihdr[4..8].copy_from_slice(&h.to_be_bytes());
    let mut out = png[..8].to_vec();
    out.extend(png_chunk(b"IHDR", &ihdr));
    out.extend(&png[AFTER_IHDR..]);
    out
}

/// The PNG made an APNG: an `acTL` chunk after IHDR.
#[must_use]
pub(crate) fn png_animated(png: &[u8]) -> Vec<u8> {
    let mut actl = 1u32.to_be_bytes().to_vec();
    actl.extend(0u32.to_be_bytes());
    let mut out = png[..AFTER_IHDR].to_vec();
    out.extend(png_chunk(b"acTL", &actl));
    out.extend(&png[AFTER_IHDR..]);
    out
}

fn riff_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut chunk = kind.to_vec();
    chunk.extend((data.len() as u32).to_le_bytes());
    chunk.extend(data);
    if data.len() % 2 == 1 {
        chunk.push(0);
    }
    chunk
}

fn le24(value: u32) -> [u8; 3] {
    let [a, b, c, _] = value.to_le_bytes();
    [a, b, c]
}

/// An animated WebP of one frame, wrapping a lossless still's bitstream.
#[must_use]
pub(crate) fn webp_animated(w: u32, h: u32, still: &[u8]) -> Vec<u8> {
    assert_eq!(&still[12..16], b"VP8L", "a simple lossless still");
    let vp8l_len = u32::from_le_bytes(still[16..20].try_into().expect("len")) as usize;
    let vp8l = &still[20..20 + vp8l_len];
    let mut vp8x = vec![0x02 | 0x10, 0, 0, 0];
    vp8x.extend(le24(w - 1));
    vp8x.extend(le24(h - 1));
    let mut anim = vec![0, 0, 0, 0];
    anim.extend(0u16.to_le_bytes());
    let mut anmf = Vec::new();
    anmf.extend(le24(0));
    anmf.extend(le24(0));
    anmf.extend(le24(w - 1));
    anmf.extend(le24(h - 1));
    anmf.extend(le24(100));
    anmf.push(0);
    anmf.extend(riff_chunk(b"VP8L", vp8l));
    let mut body = b"WEBP".to_vec();
    body.extend(riff_chunk(b"VP8X", &vp8x));
    body.extend(riff_chunk(b"ANIM", &anim));
    body.extend(riff_chunk(b"ANMF", &anmf));
    let mut out = b"RIFF".to_vec();
    out.extend((body.len() as u32).to_le_bytes());
    out.extend(body);
    out
}

/// Decodes a PNG the organ made, with the codec crate alone.
#[must_use]
pub(crate) fn decode_png(bytes: &[u8]) -> image::RgbaImage {
    image::load_from_memory_with_format(bytes, image::ImageFormat::Png)
        .expect("the export decodes")
        .to_rgba8()
}
