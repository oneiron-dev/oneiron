//! The machine's memory as the document engine's resource port (Rule 5;
//! FIX 8569, 8574, 8596, 8598, 9617).
//!
//! Office reads and edits reserve the memory their packages and XML trees
//! take from the same line as every other lease here, before they allocate
//! it. A reservation that fits at once is admitted at once, as before; one
//! that does not waits its fair turn for the host's queue wait
//! (`limits.queue_wait_timeout_ms`), measured from that reservation and never
//! past a deadline the caller gave the operation, and only then refuses,
//! typed: the machine's floor when the work's MEASURED need cannot fit even
//! on an idle machine, else the wait that ran out. An estimate (a declared
//! ZIP size, a tree's node overhead, the reservation step) never meets the
//! floor at once (Engine 10-22 20:0x): when only the estimate could never
//! fit, the measured need is leased instead, in the reservation step, and the
//! machine's live reading carries what the work then really allocates. A
//! checkpoint stops the work only at a deadline its caller gave the
//! operation; the host adds none.
//!
//! A hold the work drops once its bytes are allocated hands them to that
//! live reading. Where the machine's memory cannot be read live, nothing
//! would carry them, so the dropped hold's bytes stay leased, named
//! allocated, until the operation itself ends (FIX 10589).

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use oneiron::office_body::{DocumentMemory, RESERVE_STEP, ResourcePort, ResourceRefusal};

use crate::machine::{MachineMemory, MemoryLease, MemoryRefusal};

/// The server's machine memory line, as document operations reserve from it.
pub(crate) struct DocumentFloor {
    pub(crate) memory: MachineMemory,
    /// How long one reservation waits its turn: the host's queue wait.
    pub(crate) wait: Duration,
}

impl DocumentMemory for DocumentFloor {
    fn operation(&self, deadline: Option<Instant>) -> Arc<dyn ResourcePort> {
        Arc::new(DocumentLease {
            allocated: Arc::new(Mutex::new(self.memory.empty_lease())),
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
    /// A deadline the operation's caller gave it, when it has one: fixed
    /// for the whole operation, never renewed by a nested read.
    deadline: Option<Instant>,
    /// The bytes of the operation's dropped holds, kept leased until the
    /// operation ends where no live reading carries them (FIX 10589).
    allocated: Arc<Mutex<MemoryLease>>,
}

/// One reservation's lease, as the work holds it. Dropped, its bytes go back
/// to the line where the live reading then carries them, and otherwise move
/// into the operation's allocated lease (FIX 10589).
struct DocumentHold {
    lease: Option<MemoryLease>,
    allocated: Arc<Mutex<MemoryLease>>,
}

impl Drop for DocumentHold {
    fn drop(&mut self) {
        let Some(lease) = self.lease.take() else {
            return;
        };
        if oneiron_contracts::limit_ask::available_memory_bytes().is_none() {
            self.allocated
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .absorb_allocated(lease);
        }
    }
}

impl DocumentLease {
    /// When one reservation stops waiting: the host's queue wait from now,
    /// or the caller's deadline when that comes first.
    fn until(&self) -> Instant {
        let wait = Instant::now() + self.wait;
        self.deadline.map_or(wait, |deadline| deadline.min(wait))
    }
}

impl ResourcePort for DocumentLease {
    fn reserve(&self, bytes: u64, measured: u64) -> Result<Box<dyn Send + Sync>, ResourceRefusal> {
        let until = self.until();
        let leased = match self.memory.lease(bytes, until) {
            // Only the estimate past the measured need can never fit: the
            // measured need, in the reservation step, waits its turn instead.
            Err(MemoryRefusal::Floor { available, .. }) if measured <= available => self
                .memory
                .lease(measured.max(RESERVE_STEP).min(available), until),
            leased => leased,
        };
        match leased {
            Ok(lease) => Ok(Box::new(DocumentHold {
                lease: Some(lease),
                allocated: Arc::clone(&self.allocated),
            })),
            Err(MemoryRefusal::Floor { available, .. }) => Err(ResourceRefusal::MemoryFloor {
                needed: measured,
                available,
            }),
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
