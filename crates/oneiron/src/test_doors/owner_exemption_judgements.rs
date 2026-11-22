//! Door for `tests/owner_exemption_judged_once_per_read.rs` (row
//! [OWNER-EXEMPTION-LIFECYCLE-FOLD-PER-ROW]): counts the owner relationship
//! exemption judgements (`memory::owner_exemption_holds_in_txn`, whose
//! liveness test folds the identity lifecycle) made on this thread. A test
//! can then hold one read's count steady as the read's rows grow, without
//! timing anything.

use std::cell::Cell;

thread_local! {
    static JUDGEMENTS: Cell<usize> = const { Cell::new(0) };
}

/// Runs `run` and returns its value with the number of owner exemption
/// judgements made on this thread while it ran.
pub fn count_owner_exemption_judgements<T>(run: impl FnOnce() -> T) -> (T, usize) {
    JUDGEMENTS.with(|judgements| judgements.set(0));
    let value = run();
    (value, JUDGEMENTS.with(Cell::take))
}

/// The count point: `owner_exemption_holds_in_txn` judges one owner.
pub(crate) fn record_judgement() {
    JUDGEMENTS.with(|judgements| judgements.set(judgements.get().saturating_add(1)));
}
