//! Moved from `crates/oneiron/src/sync/federation_burst/payload.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::host_memory::MachineMemory;
use oneiron_contracts::host_memory::MemoryLease;
use oneiron_contracts::host_memory::MemoryRefusal;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Instant;

pub fn reserve_memory(size: u64) -> oneiron_base::error::Result<MemoryLease> {
    MachineMemory::process()
        .lease(size, Instant::now())
        .map_err(|refusal| {
            let kind = match refusal {
                MemoryRefusal::Floor { .. } => std::io::ErrorKind::OutOfMemory,
                MemoryRefusal::WaitedOut { .. } => std::io::ErrorKind::WouldBlock,
            };
            oneiron_base::error::Error::Io(std::io::Error::new(
                kind,
                format!("federation payload memory: {refusal:?}"),
            ))
        })
}
