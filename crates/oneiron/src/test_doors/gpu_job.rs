//! A gate in a GPU job chunk's end, between the write that ends the chunk and
//! the settlement of that chunk's permit: the window in which a resume or a
//! cancel of the next chunk runs (review round 2 of #8063 and #8064). Compiled
//! only under `--cfg oneiron_test_support`.

use std::sync::{Arc, Barrier, Mutex, MutexGuard, PoisonError};

use crate::EntityId;

/// The gates set for the next end of each job's chunk.
static END_COMMIT_GATES: Mutex<Vec<(EntityId, Arc<Barrier>)>> = Mutex::new(Vec::new());

/// The next end of `job`'s chunk waits at `gate` twice right after its write
/// committed and before it settles the chunk's permit: once on arriving, once
/// to go on. The test's other side runs between.
pub fn gate_next_end_commit(job: EntityId, gate: Arc<Barrier>) {
    gates().push((job, gate));
}

/// Waits at the gate set for `job`'s next end, if any, holding no lock.
pub(crate) fn pass_end_commit_gate(job: &EntityId) {
    let gate = {
        let mut gates = gates();
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

fn gates() -> MutexGuard<'static, Vec<(EntityId, Arc<Barrier>)>> {
    END_COMMIT_GATES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}
