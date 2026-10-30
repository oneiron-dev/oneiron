//! A forward reader over a sealed bundle section's payload, every read
//! bounded by the bytes left.

use super::malformed;
use crate::error::Result;

/// A forward reader over a section's payload.
pub(super) struct Reader<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) at: usize,
}

impl<'a> Reader<'a> {
    pub(super) fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(malformed)?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| malformed())
    }

    pub(super) fn u8(&mut self) -> Result<u8> {
        self.array().map(u8::from_be_bytes)
    }

    pub(super) fn u16(&mut self) -> Result<u16> {
        self.array().map(u16::from_be_bytes)
    }

    pub(super) fn u32(&mut self) -> Result<u32> {
        self.array().map(u32::from_be_bytes)
    }

    pub(super) fn u64(&mut self) -> Result<u64> {
        self.array().map(u64::from_be_bytes)
    }

    /// Nothing may follow the last field.
    pub(super) fn finish(&self) -> Result<()> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(malformed())
        }
    }
}
