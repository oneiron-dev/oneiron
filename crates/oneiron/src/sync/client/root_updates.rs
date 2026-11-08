//! One socket's incomplete root image. Its bytes stay outside the live Loro
//! document and the durable lease mirror until the entire image is verified.

use std::time::Instant;

use crate::host_memory::{MachineMemory, MemoryLease};
use crate::sync::transport::{TAG_ROOT_PART, TransportError, decode_root_update_part};

#[derive(Default)]
pub(super) struct RootUpdateAssembly {
    pending: Option<Pending>,
}

struct Pending {
    digest: [u8; 32],
    total: usize,
    held: HeldRootUpdate,
}

pub(super) struct HeldRootUpdate {
    pub(super) bytes: Vec<u8>,
    // The buffer drops before its reservation does, including on error/reset.
    _memory: MemoryLease,
}

impl RootUpdateAssembly {
    pub(super) fn accept(
        &mut self,
        payload: &[u8],
    ) -> Result<Option<HeldRootUpdate>, TransportError> {
        let part = match decode_root_update_part(payload) {
            Ok(part) => part,
            Err(error) => {
                self.clear();
                return Err(error);
            }
        };
        if part.offset == 0 {
            self.clear();
            // This sync entry point never waits on an async worker. Only the
            // current physical-memory floor can refuse a new, oversized image.
            let mut memory = MachineMemory::process()
                .lease(part.total as u64, Instant::now())
                .map_err(|error| {
                    TransportError::Storage(format!("root update memory: {error:?}"))
                })?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(part.total).map_err(|error| {
                TransportError::Storage(format!("root update allocation: {error}"))
            })?;
            memory.materialized(part.total as u64, bytes.capacity() as u64);
            self.pending = Some(Pending {
                digest: part.digest,
                total: part.total,
                held: HeldRootUpdate {
                    bytes,
                    _memory: memory,
                },
            });
        }
        let Some(pending) = self.pending.as_mut() else {
            return Err(TransportError::InvalidPayload("root part without an image"));
        };
        if pending.digest != part.digest
            || pending.total != part.total
            || pending.held.bytes.len() != part.offset
        {
            self.clear();
            return Err(TransportError::InvalidPayload(
                "root part image or offset mismatch",
            ));
        }
        pending.held.bytes.extend_from_slice(part.bytes);
        if pending.held.bytes.len() < pending.total {
            return Ok(None);
        }
        let Some(done) = self.pending.take() else {
            return Err(TransportError::InvalidPayload(
                "missing completed root image",
            ));
        };
        if blake3::hash(&done.held.bytes).as_bytes() != &done.digest {
            return Err(TransportError::InvalidPayload(
                "root update digest mismatch",
            ));
        }
        Ok(Some(done.held))
    }

    pub(super) fn clear(&mut self) {
        self.pending = None;
    }
}

impl super::base::SyncClient {
    pub(crate) fn root_update_pending(&self) -> bool {
        self.root_parts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .is_some()
    }

    /// The logical openings `frame` completes in initial sync, once handled:
    /// one, but none for a root part whose image is still incomplete, so a
    /// large root counts once.
    pub(crate) fn logical_openings(&self, frame: &[u8]) -> usize {
        usize::from(frame.first() != Some(&TAG_ROOT_PART) || !self.root_update_pending())
    }

    pub(crate) fn reset_root_parts(&self) {
        self.root_parts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}
