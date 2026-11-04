//! The lift sweep's typed acceptance for the tracker pull-page cursor row
//! (`LINEAR_PULL_CURSOR`). The tracker mirror (`task_verb`) writes the row;
//! its side-table declaration names this check.
use crate::side_table::Raw;

/// Whether a masked copy of a `LINEAR_PULL_CURSOR` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn linear_pull_cursor_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<String, Raw>(bytes)
}
