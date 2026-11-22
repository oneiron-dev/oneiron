//! Doors for `tests/arc_summary_live_support.rs`
//! (ARC-SUMMARY-SERVED-AFTER-ITS-PROPOSALS-LOSE-SUPPORT): write one nightly
//! arc summary over named proposals through the merge's own draft and writer,
//! and read the records a claim's consolidation envelope cites. Thin wrappers
//! over the production code only. Compiled only under
//! `--cfg oneiron_test_support` (`test_doors`); hidden, never API.

use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

/// Writes `narrative` as the arc summary of `proposals` under `attempt`, as
/// the nightly merge writes one exposure group's narrative, and returns the
/// arc summary's id.
///
/// # Errors
///
/// A proposal the Dreamer does not read live, an unknown attempt, an empty
/// `proposals`, or the write's own.
pub fn write_arc_summary(
    vault: &Vault,
    attempt: AttemptId,
    proposals: &[EntityId],
    narrative: &str,
) -> Result<EntityId> {
    crate::dreamer_consolidation::nightly_merge::doors::write_arc_summary(
        vault, attempt, proposals, narrative,
    )
}

/// The records `claim`'s consolidation envelope cites: none for a claim with
/// no envelope.
///
/// # Errors
///
/// The vault's; an unknown claim.
pub fn cited_refs(vault: &Vault, claim: &EntityId) -> Result<Vec<EntityId>> {
    let body = vault.get_claim(claim)?.ok_or(Error::EntityNotFound)?;
    Ok(crate::provenance::consolidation_refs(&body))
}
