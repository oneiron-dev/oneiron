//! The machine's memory as the document engine's resource port (Rule 5;
//! FIX 8569, 8574, 8596, 8598, 9617).
//!
//! Office reads and edits reserve the memory their packages and XML trees
//! take from the same line as every other lease here, before they allocate
//! it. A reservation that fits at once is admitted at once, as before; one
//! that does not waits its fair turn for the host's queue wait
//! (`limits.queue_wait_timeout_ms`), measured from that reservation, and only
//! then refuses, typed: the machine's floor when it cannot fit even on an
//! idle machine, else the wait that ran out. A checkpoint stops the work only
//! at a deadline its caller gave the operation; the host adds none.

use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::office_body::{DocumentMemory, ResourcePort, ResourceRefusal};

use crate::machine::{MachineMemory, MemoryRefusal};

/// The server's machine memory line, as document operations reserve from it.
pub(crate) struct DocumentFloor {
    pub(crate) memory: MachineMemory,
    /// How long one reservation waits its turn: the host's queue wait.
    pub(crate) wait: Duration,
}

impl DocumentMemory for DocumentFloor {
    fn operation(&self, deadline: Option<Instant>) -> Arc<dyn ResourcePort> {
        Arc::new(DocumentLease {
            memory: self.memory.clone(),
            wait: self.wait,
            deadline,
        })
    }
}

/// One document operation's port on the line.
struct DocumentLease {
    memory: MachineMemory,
    wait: Duration,
    /// A deadline the operation's caller gave it, when it has one.
    deadline: Option<Instant>,
}

impl ResourcePort for DocumentLease {
    fn reserve(&self, bytes: u64) -> Result<Box<dyn Send + Sync>, ResourceRefusal> {
        match self.memory.lease(bytes, Instant::now() + self.wait) {
            Ok(lease) => Ok(Box::new(lease)),
            Err(MemoryRefusal::Floor { needed, available }) => {
                Err(ResourceRefusal::MemoryFloor { needed, available })
            }
            Err(MemoryRefusal::WaitedOut { .. }) => Err(ResourceRefusal::Deadline),
        }
    }

    fn checkpoint(&self) -> Result<(), ResourceRefusal> {
        match self.deadline {
            Some(deadline) if Instant::now() >= deadline => Err(ResourceRefusal::Deadline),
            _ => Ok(()),
        }
    }
}
