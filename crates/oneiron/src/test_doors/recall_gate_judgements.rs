//! Door for `tests/recall_gate_judges_once.rs` (row [RECALL-EXPANDED-ROW-FACTS-REREAD]):
//! counts the full actor judgements a recall's candidate gate
//! (`ScopedRead::recall_candidate_gate`) makes on this thread, per retrieval
//! snapshot and row. A test can then hold each row to one judgement in each
//! snapshot without timing anything.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use crate::entity_id::EntityId;

thread_local! {
    static NEXT_SNAPSHOT: Cell<u64> = const { Cell::new(0) };
    static JUDGEMENTS: RefCell<HashMap<(u64, EntityId), usize>> = RefCell::new(HashMap::new());
}

/// Runs `run` and returns its value with the full judgements the recall gate
/// made on this thread: for each retrieval snapshot (numbered from 0 in the
/// order `run` opened them) and row, how many times the gate judged the row in
/// that snapshot's own transaction.
pub fn count_recall_gate_judgements<T>(
    run: impl FnOnce() -> T,
) -> (T, HashMap<(u64, EntityId), usize>) {
    NEXT_SNAPSHOT.with(|next| next.set(0));
    JUDGEMENTS.with(|judgements| judgements.borrow_mut().clear());
    let value = run();
    let judgements = JUDGEMENTS.with(|judgements| std::mem::take(&mut *judgements.borrow_mut()));
    (value, judgements)
}

/// The number of the snapshot gate the recall gate opens now
/// (`CandidateGate::in_txn`).
pub(crate) fn open_snapshot() -> u64 {
    NEXT_SNAPSHOT.with(|next| {
        let snapshot = next.get();
        next.set(snapshot.saturating_add(1));
        snapshot
    })
}

/// The count point: the gate judges `id` in full in `snapshot`'s own
/// transaction.
pub(crate) fn record_judgement(snapshot: u64, id: &EntityId) {
    JUDGEMENTS.with(|judgements| {
        let mut judgements = judgements.borrow_mut();
        let count = judgements.entry((snapshot, *id)).or_insert(0);
        *count = count.saturating_add(1);
    });
}
