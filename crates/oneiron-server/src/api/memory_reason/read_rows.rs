//! Raw scoped-read rows and bodies on the request's memory line.

use oneiron::claim::{PointRead, ReadRow};
use oneiron::host_memory::{MachineMemory, MemoryLease};

pub(super) struct ReadRows {
    // Rows and their bodies drop before their memory charge.
    rows: Vec<Option<ReadRow>>,
    memory: MemoryLease,
}

impl ReadRows {
    pub(super) fn new(memory: &MachineMemory, rows: Vec<Option<ReadRow>>) -> Self {
        let mut frame = Self {
            rows,
            memory: memory.empty_lease(),
        };
        let backing = (frame.rows.capacity() as u64)
            .saturating_mul(std::mem::size_of::<Option<ReadRow>>() as u64);
        let bodies = frame
            .rows
            .iter()
            .flatten()
            .filter_map(|row| row.body.as_ref())
            .fold(0u64, |bytes, body| {
                bytes.saturating_add(body.capacity() as u64)
            });
        frame.memory.materialized(0, backing.saturating_add(bodies));
        frame
    }

    pub(super) fn len(&self) -> usize {
        self.rows.len()
    }

    pub(super) fn drain(&mut self) -> std::vec::Drain<'_, Option<ReadRow>> {
        self.rows.drain(..)
    }
}

pub(super) struct ReadRequests<'r> {
    // The request vector drops before its memory charge.
    reads: Vec<PointRead<'r>>,
    memory: MemoryLease,
}

impl<'r> ReadRequests<'r> {
    pub(super) fn new(memory: &MachineMemory, reads: Vec<PointRead<'r>>) -> Self {
        let mut requests = Self {
            reads,
            memory: memory.empty_lease(),
        };
        let backing = (requests.reads.capacity() as u64)
            .saturating_mul(std::mem::size_of::<PointRead<'r>>() as u64);
        requests.memory.materialized(0, backing);
        requests
    }

    pub(super) fn as_slice(&self) -> &[PointRead<'r>] {
        &self.reads
    }
}
