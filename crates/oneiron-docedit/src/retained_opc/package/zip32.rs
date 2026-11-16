//! Classic ZIP's little-endian record fields, and the DEFLATE a part is
//! written with, for the package's reader and copy-through writer.

use super::{Error, Result};
use crate::resource::Dimension;
use miniz_oxide::DataFormat;
use miniz_oxide::deflate::core::CompressorOxide;
use miniz_oxide::deflate::stream::deflate as deflate_stream;
use miniz_oxide::{MZFlush, MZStatus};

pub(super) fn get16(bytes: &[u8], at: usize) -> Result<u16> {
    let raw: [u8; 2] = bytes
        .get(at..at.checked_add(2).ok_or(Error::Invalid("offset overflow"))?)
        .ok_or(Error::Invalid("truncated ZIP"))?
        .try_into()
        .map_err(|_| Error::Invalid("truncated ZIP"))?;
    Ok(u16::from_le_bytes(raw))
}
pub(super) fn get32(bytes: &[u8], at: usize) -> Result<u32> {
    let raw: [u8; 4] = bytes
        .get(at..at.checked_add(4).ok_or(Error::Invalid("offset overflow"))?)
        .ok_or(Error::Invalid("truncated ZIP"))?
        .try_into()
        .map_err(|_| Error::Invalid("truncated ZIP"))?;
    Ok(u32::from_le_bytes(raw))
}
pub(super) fn patch16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
pub(super) fn patch32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
pub(super) fn as_u32(size: usize) -> Result<u32> {
    u32::try_from(size)
        .map_err(|_| Error::capacity_hit(Dimension::ZipBytes, size, u32::MAX as usize))
}

/// The level `flate2::Compression::default()` names, which parts were
/// written with before this module compressed them itself.
const LEVEL: u8 = 6;
/// Output handed to the sink per step.
const CHUNK: usize = 32 * 1024;

/// Raw DEFLATE of `data`, handing each compressed chunk to `sink`.
///
/// One implementation in every build. flate2 takes its backend from the
/// build's whole feature set: miniz_oxide in this crate alone, zlib-rs once
/// any crate in the graph asks for it (the engine's does, through calamine's
/// zip). The two write different bytes for one part, and a stored Office
/// receipt names the SHA-256 of the exact package PowerPoint opened, so a
/// package's bytes must not depend on which crate links this one. The calls
/// are flate2's miniz_oxide ones, so the bytes are the ones this crate wrote
/// through flate2 alone.
fn deflate_into(data: &[u8], mut sink: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
    let mut compressor = CompressorOxide::default();
    compressor.set_format_and_level(DataFormat::Raw, LEVEL);
    let mut out = vec![0_u8; CHUNK];
    let mut input = data;
    loop {
        let flush = if input.is_empty() {
            MZFlush::Finish
        } else {
            MZFlush::None
        };
        let step = deflate_stream(&mut compressor, input, &mut out, flush);
        let status = step.status.map_err(|_| Error::Edit("compression failed"))?;
        sink(
            out.get(..step.bytes_written)
                .ok_or(Error::Edit("compression failed"))?,
        )?;
        input = input
            .get(step.bytes_consumed..)
            .ok_or(Error::Edit("compression failed"))?;
        if status == MZStatus::StreamEnd {
            return Ok(());
        }
        if step.bytes_consumed == 0 && step.bytes_written == 0 {
            return Err(Error::Edit("compression failed"));
        }
    }
}

/// The raw DEFLATE bytes a part is written with.
pub(super) fn deflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    deflate_into(data, |chunk| {
        out.extend_from_slice(chunk);
        Ok(())
    })?;
    Ok(out)
}

/// How many bytes `data` takes under `method`, without keeping them.
pub(super) fn compressed_length(method: u16, data: &[u8]) -> Result<usize> {
    if method == 0 {
        return Ok(data.len());
    }
    let mut length = 0_usize;
    deflate_into(data, |chunk| {
        length = length
            .checked_add(chunk.len())
            .ok_or(Error::Edit("compression failed"))?;
        Ok(())
    })?;
    Ok(length)
}
