//! The `erased` end of a feedback triage revision (FIX 7551). Once the owner
//! erases a revision's evidence ASSET, no finding can cite it, so the
//! revision is settled erased: no sweep queues it again, its evidence is
//! never retained again (its handoff row stays, so a walk that meets the
//! revision again finds it handed off), a job still queued triages nothing,
//! a result that would file findings citing it is refused, and the owner's
//! status lists it by name only. Only the permanent `dt:` marker an erase
//! leaves on the ASSET proves the erase; an item that cannot be read for any
//! other reason keeps today's re-queue.
use super::{FeedbackTriageHandoff, HANDOFFS};
use crate::{Error, Result, Vault};

/// Whether the owner erased `handoff`'s evidence ASSET: settled erased
/// already, or carrying the `dt:` marker an erase leaves.
pub(super) fn evidence_erased_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    handoff: &FeedbackTriageHandoff,
) -> Result<bool> {
    Ok(handoff.erased_at.is_some()
        || vault.local_hard_delete_marker_exists_in_txn(txn, &handoff.evidence)?)
}

/// Settles `handoff`, stored under `key`, erased at `now` when the owner
/// erased its evidence, in the sweep's write; `true` when it did, and the
/// sweep then queues nothing for it. The part graph a long item left goes
/// with it (FIX 7549): its answers were drawn from the erased item.
pub(super) fn settle_erased_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    handoff: &mut FeedbackTriageHandoff,
    now: u64,
) -> Result<bool> {
    if !vault.local_hard_delete_marker_exists_in_txn(txn, &handoff.evidence)? {
        return Ok(false);
    }
    handoff.erased_at = Some(now);
    handoff.work = None;
    HANDOFFS.put(&vault.store, txn, key, handoff)?;
    Ok(true)
}

/// Refuses a result for `handoff` once its evidence was erased, so the write
/// that would file findings citing the erased ASSET rolls back; the next
/// sweep settles the revision erased.
pub(super) fn refuse_erased_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    handoff: &FeedbackTriageHandoff,
) -> Result<()> {
    if evidence_erased_in_txn(vault, txn, handoff)? {
        return Err(Error::Refused(
            "the owner erased this feedback item's evidence: its triage files nothing and is \
             not queued again"
                .into(),
        ));
    }
    Ok(())
}
