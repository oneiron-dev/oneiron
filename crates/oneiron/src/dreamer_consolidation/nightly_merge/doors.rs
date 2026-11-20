//! Doors for `tests/arc_summary_live_support.rs`
//! (ARC-SUMMARY-SERVED-AFTER-ITS-PROPOSALS-LOSE-SUPPORT): one arc summary
//! written over named proposals as the nightly merge writes one exposure
//! group's narrative, through the merge's own draft and writer. Compiled only
//! under `--cfg oneiron_test_support` (`test_doors`); hidden, never API.

use super::write::MergeDraft;
use super::{Proposal, merge_read, merge_writer, recheck_in_txn};
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::{EntityId, Error, Result, Vault};

/// Writes `narrative` as the arc summary of `proposals` under `attempt`, as
/// the nightly merge writes one group's narrative: the Dreamer reads each
/// proposal live, the commit reads every proposal again, and the draft takes
/// the first proposal's exposure and cites what the proposals stand on.
/// Returns the arc summary's id.
///
/// # Errors
///
/// A proposal the Dreamer does not read live, an unknown attempt, an empty
/// `proposals`, or the write's own.
pub(crate) fn write_arc_summary(
    vault: &Vault,
    attempt: AttemptId,
    proposals: &[EntityId],
    narrative: &str,
) -> Result<EntityId> {
    let actor = vault.dreamer_authority()?;
    let read = merge_read(vault, actor)?;
    let status = DreamerRunnerStore::new(vault)
        .status(attempt)?
        .ok_or(Error::EntityNotFound)?;
    let members = {
        let txn = vault.store.env.read_txn()?;
        let mut members = Vec::with_capacity(proposals.len());
        for id in proposals {
            let raw = read
                .entity_raw_live_in(&txn, id)?
                .ok_or(Error::EntityNotFound)?;
            let body = vault
                .get_claim_in_txn(&txn, id)?
                .ok_or(Error::EntityNotFound)?;
            members.push(Proposal {
                id: *id,
                raw,
                body,
                children: vec![attempt],
            });
        }
        members
    };
    let members: Vec<&Proposal> = members.iter().collect();
    let writer = merge_writer(vault, actor, &status, crate::unix_seconds_now());
    let outputs = vault.with_write_txn_grouped(|txn| {
        recheck_in_txn(&read, txn, &members)?;
        let draft = MergeDraft::ArcSummary {
            members: members.as_slice(),
            narrative: narrative.into(),
        }
        .in_txn(&read, txn);
        writer.claims_in_txn(txn, vec![draft])
    })?;
    outputs.first().copied().ok_or(Error::EntityNotFound)
}
