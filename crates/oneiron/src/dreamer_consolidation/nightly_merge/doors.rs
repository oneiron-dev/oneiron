//! Doors for `tests/arc_summary_live_support.rs`
//! (ARC-SUMMARY-SERVED-AFTER-ITS-PROPOSALS-LOSE-SUPPORT): one arc summary
//! written over named proposals as the nightly merge writes one exposure
//! group's narrative, through the merge's own draft and writer. Compiled only
//! under `--cfg oneiron_test_support` (`test_doors`); hidden, never API.

use super::{MERGE_IDS, NightlyWrite, Proposal, merge_read, recheck_in_txn, scoped_draft};
use crate::attempt_queue::AttemptId;
use crate::claim::ClaimSubject;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::{ClaimCandidate, EntityId, Error, Result, Vault};

/// Writes `narrative` as the arc summary of `proposals` under `attempt`, as
/// the nightly merge writes one group's narrative: the Dreamer reads each
/// proposal live, the draft takes the first proposal's exposure, and the
/// commit reads every proposal again before it writes. Returns the arc
/// summary's id.
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
    let first = &members
        .first()
        .ok_or(Error::InvalidClaimBody("an arc summary needs a proposal"))?
        .body;
    let candidate = ClaimCandidate::new(
        "dreamer.arc.summary",
        ClaimSubject::Entity(first.scope_project),
        narrative.into(),
        1.0,
    );
    let draft = scoped_draft(candidate, first, &members);
    let writer = NightlyWrite {
        vault,
        actor,
        attempt: &status,
        ids: MERGE_IDS,
        now: crate::unix_seconds_now(),
    };
    let outputs = vault.with_write_txn_grouped(|txn| {
        recheck_in_txn(&read, txn, &members)?;
        writer.claims_in_txn(txn, vec![draft])
    })?;
    outputs.first().copied().ok_or(Error::EntityNotFound)
}
