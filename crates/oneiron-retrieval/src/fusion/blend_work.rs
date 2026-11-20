//! Door for `oneiron`'s `tests/blend_columns_once.rs` (row
//! [RECALL-FUSION-COLUMNS-TWICE]): counts, on this thread, the linear-log
//! blends that score candidates and the passes that compute their normalized
//! signal columns. A test can then hold each blend to one column pass without
//! timing anything. Compiled only under `--cfg oneiron_test_support`.

use std::cell::Cell;

thread_local! {
    static BLENDS: Cell<usize> = const { Cell::new(0) };
    static COLUMN_PASSES: Cell<usize> = const { Cell::new(0) };
}

/// The blend work one run did on this thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlendWork {
    /// Calls that scored a candidate set (`linear_log_blend_scores_with_weights`).
    pub blends: usize,
    /// Passes that computed a candidate set's normalized signal columns.
    pub column_passes: usize,
}

/// Runs `run` and returns its value with the blend work it did on this
/// thread.
pub fn count_blend_work<T>(run: impl FnOnce() -> T) -> (T, BlendWork) {
    BLENDS.with(|count| count.set(0));
    COLUMN_PASSES.with(|count| count.set(0));
    let value = run();
    let work = BlendWork {
        blends: BLENDS.with(Cell::take),
        column_passes: COLUMN_PASSES.with(Cell::take),
    };
    (value, work)
}

/// The count point of a blend that scores a candidate set.
pub(super) fn record_blend() {
    BLENDS.with(|count| count.set(count.get().saturating_add(1)));
}

/// The count point of a normalized-column pass.
pub(super) fn record_column_pass() {
    COLUMN_PASSES.with(|count| count.set(count.get().saturating_add(1)));
}
