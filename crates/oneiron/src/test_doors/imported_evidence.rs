//! Doors for `tests/foreign_archive_speakers.rs` (fix list row 15412, review
//! of #7544 round 1): whether evidence counts as imported words, as the
//! Dreamer's promotion writer reads it (`ingest::history::
//! imported_evidence_in_txn`). A thin wrapper over the production read only.
//! Compiled only under `--cfg oneiron_test_support`; hidden, never API.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

/// Whether evidence `refs`, citing the MESSAGE rows `cited`, is imported
/// words in `vault`: the fact on which the promotion writer makes a claim
/// `Imported`, whatever meet its caller computed.
///
/// # Errors
///
/// The vault's read faults.
#[doc(hidden)]
pub fn imported_evidence(vault: &Vault, refs: &[EntityId], cited: &[EntityId]) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(crate::ingest::history::imported_evidence_in_txn(vault, &txn, refs, cited)?.imported)
}
