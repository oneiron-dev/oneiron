//! A gate in a GPU job chunk's end, between the write that ends the chunk and
//! the settlement of that chunk's permit: the window in which a resume or a
//! cancel of the next chunk runs (review round 2 of #8063 and #8064). Compiled
//! only under `--cfg oneiron_test_support`. The gates live on the host's
//! [`GpuJobPermits`], never in a process-global static.

use std::sync::{Arc, Barrier, MutexGuard, PoisonError};

use crate::EntityId;
use crate::gpu_job::GpuJobPermits;

/// The next end of `job`'s chunk on the host holding `permits` waits at
/// `gate` twice right after its write committed and before it settles the
/// chunk's permit: once on arriving, once to go on. The test's other side
/// runs between.
pub fn gate_next_end_commit(permits: &GpuJobPermits, job: EntityId, gate: Arc<Barrier>) {
    gates(permits).push((job, gate));
}

/// Waits at the gate set for `job`'s next end, if any, holding no lock.
pub(crate) fn pass_end_commit_gate(permits: &GpuJobPermits, job: &EntityId) {
    let gate = {
        let mut gates = gates(permits);
        gates
            .iter()
            .position(|(id, _)| id == job)
            .map(|at| gates.remove(at).1)
    };
    if let Some(gate) = gate {
        gate.wait();
        gate.wait();
    }
}

fn gates(permits: &GpuJobPermits) -> MutexGuard<'_, Vec<(EntityId, Arc<Barrier>)>> {
    permits
        .end_commit_gates
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}
