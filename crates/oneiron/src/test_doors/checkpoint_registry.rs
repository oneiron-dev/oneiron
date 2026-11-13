//! The checkpoint payload registry's side-table gaps, for
//! `tests/checkpoint_registry_rows.rs`. Compiled only under
//! `--cfg oneiron_test_support`; never API.

/// Every payload registry gap that holds a side table out of the
/// compartments, as a capture receipt names it.
pub fn side_table_registry_gaps() -> Vec<String> {
    crate::recovery::checkpoint::side_table_registry_gaps()
}
