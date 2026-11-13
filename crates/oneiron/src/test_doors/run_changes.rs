//! Doors for `tests/run_changes_journal_cost.rs`: the stored size of a run's
//! change journal rows (`memory::run_review`). Compiled only under
//! `--cfg oneiron_test_support`; never API.

use crate::Result;
use crate::vault::Vault;

/// Each stored journal row of `run`, in write order: its whole key's and its
/// value's byte lengths.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn journal_row_sizes(vault: &Vault, run: &str) -> Result<Vec<(usize, usize)>> {
    crate::memory::run_review::journal_row_sizes(vault, run)
}
