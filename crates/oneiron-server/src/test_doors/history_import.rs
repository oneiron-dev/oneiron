//! Doors for `tests/history_import_review_id_same_second.rs`
//! ([HISTORY-IMPORT-REVIEW-ID-SAME-SECOND]): the import second `own_second`
//! hands out, so a test can own seconds the way the CLI, the queue pass and
//! the hosted-import worker do.

use oneiron::Vault;

/// The second one import lands at, as `oneiron import` owns it: after every
/// write before it, so no two imports share one.
///
/// # Errors
///
/// The wait's refusal, in its own words.
pub fn own_second(vault: &Vault) -> Result<u64, String> {
    crate::commands::own_second(vault).map_err(|error| format!("{error:#}"))
}
