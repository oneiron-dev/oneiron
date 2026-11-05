//! Retained citable evidence on the process memory line.

use oneiron::host_memory::{MachineMemory, MemoryLease};

use super::MemoryReasonEvidence;

pub(super) struct CollectedEvidence {
    // The retained rows and their strings drop before their memory charge.
    rows: Vec<MemoryReasonEvidence>,
    memory: MemoryLease,
}

impl CollectedEvidence {
    pub(super) fn with_capacity(memory: &MachineMemory, capacity: usize) -> Self {
        let rows = Vec::with_capacity(capacity);
        let mut memory = memory.empty_lease();
        memory.materialized(0, backing_bytes(rows.capacity()));
        Self { rows, memory }
    }

    pub(super) fn push(&mut self, row: MemoryReasonEvidence) {
        let strings = (row.short_id.capacity() as u64)
            .saturating_add(row.kind.capacity() as u64)
            .saturating_add(row.text.capacity() as u64);
        let previous_capacity = self.rows.capacity();
        self.rows.push(row);
        let added_backing = backing_bytes(self.rows.capacity() - previous_capacity);
        self.memory
            .materialized(0, strings.saturating_add(added_backing));
    }

    pub(super) fn as_slice(&self) -> &[MemoryReasonEvidence] {
        &self.rows
    }
}

fn backing_bytes(capacity: usize) -> u64 {
    (capacity as u64).saturating_mul(std::mem::size_of::<MemoryReasonEvidence>() as u64)
}
