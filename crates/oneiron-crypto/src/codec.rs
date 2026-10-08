//! Canonical encoding primitives: big-endian integers, fixed-size fields and
//! length-prefixed byte strings, every read bounded.

use crate::error::{Error, Result};

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn take(&mut self, len: usize, field: &'static str) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(Error::Truncated { field })?;
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub(crate) fn array<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N, field)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self, field: &'static str) -> Result<u8> {
        Ok(self.array::<1>(field)?[0])
    }

    pub(crate) fn u16(&mut self, field: &'static str) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array(field)?))
    }

    pub(crate) fn u32(&mut self, field: &'static str) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array(field)?))
    }

    pub(crate) fn u64(&mut self, field: &'static str) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array(field)?))
    }

    /// A `u8` length prefix followed by that many bytes, length in `min..=max`.
    pub(crate) fn lp8(&mut self, field: &'static str, min: usize, max: usize) -> Result<&'a [u8]> {
        let len = usize::from(self.u8(field)?);
        check_len(field, len, min, max)?;
        self.take(len, field)
    }

    /// Refuses any bytes after the last field.
    pub(crate) fn finish(&self) -> Result<()> {
        match self.bytes.len() - self.pos {
            0 => Ok(()),
            extra => Err(Error::TrailingBytes { extra }),
        }
    }
}

pub(crate) fn check_len(field: &'static str, len: usize, min: usize, max: usize) -> Result<()> {
    if (min..=max).contains(&len) {
        Ok(())
    } else {
        Err(Error::FieldLength {
            field,
            len,
            min,
            max,
        })
    }
}

/// Appends a `u8` length prefix and the bytes; the caller has checked the bound.
pub(crate) fn put_lp8(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u8::try_from(bytes.len()).unwrap_or(u8::MAX);
    out.push(len);
    out.extend_from_slice(&bytes[..usize::from(len)]);
}
