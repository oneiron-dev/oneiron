//! Compare an encoded value with existing bytes without retaining its output.

use std::io::{self, Write};

pub(super) struct ByteComparison<'a> {
    remaining: &'a [u8],
    equal: bool,
}

impl<'a> ByteComparison<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self {
            remaining: bytes,
            equal: true,
        }
    }

    pub(super) fn is_equal(&self) -> bool {
        self.equal && self.remaining.is_empty()
    }
}

impl Write for ByteComparison<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.equal {
            match self.remaining.strip_prefix(bytes) {
                Some(remaining) => self.remaining = remaining,
                None => self.equal = false,
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
