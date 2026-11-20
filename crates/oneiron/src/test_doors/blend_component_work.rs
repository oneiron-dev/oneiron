//! Door for `tests/blend_columns_once.rs` (row [RECALL-FUSION-COLUMNS-TWICE]):
//! counts, on this thread, the blends a retrieval runs, the passes that
//! compute their normalized signal columns, and the score-component rows each
//! rerank stage builds for its own map. A test can then hold each blend to one
//! column pass and each rerank stage to its block's rows without timing
//! anything.

use std::cell::RefCell;

use crate::fusion::blend_work::count_blend_work;

thread_local! {
    static RERANK_COMPONENT_ROWS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// The blend and rerank component work one run did on this thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlendComponentWork {
    /// Blends that scored a candidate set.
    pub blends: usize,
    /// Passes that computed a candidate set's normalized signal columns.
    pub column_passes: usize,
    /// For each rerank stage that ran, in order, the entities its own
    /// score-component map holds.
    pub rerank_component_rows: Vec<usize>,
}

/// Runs `run` and returns its value with the blend and rerank component work
/// it did on this thread.
pub fn count_blend_component_work<T>(run: impl FnOnce() -> T) -> (T, BlendComponentWork) {
    RERANK_COMPONENT_ROWS.with(|rows| rows.borrow_mut().clear());
    let (value, blend) = count_blend_work(run);
    let rerank_component_rows = RERANK_COMPONENT_ROWS.with(|rows| rows.take());
    (
        value,
        BlendComponentWork {
            blends: blend.blends,
            column_passes: blend.column_passes,
            rerank_component_rows,
        },
    )
}

/// The count point: a rerank stage built a score-component map of `rows`
/// entities.
pub(crate) fn record_rerank_component_rows(rows: usize) {
    RERANK_COMPONENT_ROWS.with(|recorded| recorded.borrow_mut().push(rows));
}
