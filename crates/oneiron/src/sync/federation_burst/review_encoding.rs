//! Memory ownership for the retained review's exact named MessagePack output.

use std::io::{self, Write};
use std::time::Instant;

use oneiron_contracts::host_memory::{MachineMemory, MemoryLease, MemoryRefusal};

use super::FederationBurstReviewBundle;

pub(super) struct EncodedReview {
    bytes: Vec<u8>,
    _memory: MemoryLease,
}

impl EncodedReview {
    pub(super) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Default)]
struct EncodedSize(usize);

impl Write for EncodedSize {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.checked_add(bytes.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::OutOfMemory, "review encoding size overflow")
        })?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn encode(bundle: &FederationBurstReviewBundle) -> crate::Result<EncodedReview> {
    let mut size = EncodedSize::default();
    rmp_serde::encode::write_named(&mut size, bundle).map_err(encode_error)?;
    let size = size.0;
    let mut memory = MachineMemory::process()
        .lease(size as u64, Instant::now())
        .map_err(|refusal| {
            let kind = match refusal {
                MemoryRefusal::Floor { .. } => io::ErrorKind::OutOfMemory,
                MemoryRefusal::WaitedOut { .. } => io::ErrorKind::WouldBlock,
            };
            crate::Error::Io(io::Error::new(
                kind,
                format!("retained federation review encoding memory: {refusal:?}"),
            ))
        })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|error| crate::Error::Io(io::Error::new(io::ErrorKind::OutOfMemory, error)))?;
    memory.materialized(size as u64, bytes.capacity() as u64);
    rmp_serde::encode::write_named(&mut bytes, bundle).map_err(encode_error)?;
    Ok(EncodedReview {
        bytes,
        _memory: memory,
    })
}

fn encode_error(error: rmp_serde::encode::Error) -> crate::Error {
    match error {
        rmp_serde::encode::Error::InvalidValueWrite(error) => {
            crate::Error::Io(io::Error::other(error))
        }
        _ => super::corrupt(),
    }
}
