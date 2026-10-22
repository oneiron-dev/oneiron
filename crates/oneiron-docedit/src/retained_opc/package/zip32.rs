//! Classic ZIP's little-endian record fields, and the compressed length a
//! part takes, for the package's reader and copy-through writer.

use super::{Error, Result};
use crate::resource::Dimension;
use flate2::{Compression, write::DeflateEncoder};
use std::io::Write;

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

struct CountedBytes(usize);
impl Write for CountedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or(std::io::ErrorKind::OutOfMemory)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(super) fn compressed_length(method: u16, data: &[u8]) -> Result<usize> {
    if method == 0 {
        return Ok(data.len());
    }
    let mut encoder = DeflateEncoder::new(CountedBytes(0), Compression::default());
    encoder
        .write_all(data)
        .map_err(|_| Error::Edit("compression failed"))?;
    let sink = encoder
        .finish()
        .map_err(|_| Error::Edit("compression failed"))?;
    Ok(sink.0)
}
