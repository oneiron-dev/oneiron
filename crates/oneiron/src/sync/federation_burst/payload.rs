//! Process-memory ownership for retained original federation payloads.

use std::fmt;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Instant;

use oneiron_contracts::host_memory::{MachineMemory, MemoryLease, MemoryRefusal};

#[derive(Clone)]
pub(in crate::sync) struct DeferredPayload(Arc<OwnedPayload>);

struct OwnedPayload {
    bytes: Vec<u8>,
    // Field order returns the bytes before releasing their physical charge.
    _memory: MemoryLease,
}

impl DeferredPayload {
    pub(super) fn copy_from_slice(source: &[u8]) -> crate::Result<Self> {
        let size = source.len() as u64;
        let mut memory = MachineMemory::process()
            .lease(size, Instant::now())
            .map_err(|refusal| {
                let kind = match refusal {
                    MemoryRefusal::Floor { .. } => std::io::ErrorKind::OutOfMemory,
                    MemoryRefusal::WaitedOut { .. } => std::io::ErrorKind::WouldBlock,
                };
                crate::Error::Io(std::io::Error::new(
                    kind,
                    format!("retained federation payload memory: {refusal:?}"),
                ))
            })?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(source.len()).map_err(|error| {
            crate::Error::Io(std::io::Error::new(std::io::ErrorKind::OutOfMemory, error))
        })?;
        memory.materialized(size, bytes.capacity() as u64);
        bytes.extend_from_slice(source);
        Ok(Self(Arc::new(OwnedPayload {
            bytes,
            _memory: memory,
        })))
    }

    pub(in crate::sync) fn as_slice(&self) -> &[u8] {
        &self.0.bytes
    }
}

impl Deref for DeferredPayload {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl PartialEq for DeferredPayload {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl fmt::Debug for DeferredPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_slice().fmt(formatter)
    }
}
