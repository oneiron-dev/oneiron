//! Fallible output buffers for request bodies.

use std::io::{self, Write};

/// Encodes a JSON body, reporting output-buffer allocation failures as I/O errors.
pub fn json_body(value: &serde_json::Value) -> serde_json::Result<Vec<u8>> {
    let mut body = FallibleBody::default();
    serde_json::to_writer(&mut body, value)?;
    Ok(body.into_bytes())
}

#[derive(Default)]
pub(crate) struct FallibleBody(Vec<u8>);

impl FallibleBody {
    pub(crate) fn with_capacity(capacity: usize) -> io::Result<Self> {
        let mut body = Self::default();
        body.0
            .try_reserve_exact(capacity)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        Ok(body)
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl Write for FallibleBody {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .try_reserve(bytes.len())
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
