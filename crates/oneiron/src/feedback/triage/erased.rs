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
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::store::Store;
use crate::{EntityId, Error, Result, Vault};

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

/// Settles each acknowledged handoff whose evidence is `id`, in the erase
/// transaction that purges it (FIX 10921): `erased_at` set to vault seconds
/// now, the part graph dropped, the row with its result kept. Only the
/// permanent hard-delete marker proves the erase, so the soft door is a
/// no-op; unacknowledged rows keep the sweep's settlement, and a row
/// settled already keeps its stamp.
pub(crate) fn erase_handoff_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if !store.port_deletion_marked(txn, DeletionMarker::HardDelete, id)? {
        return Ok(());
    }
    // Evidence is always an ASSET. Only a present, parsed non-ASSET row
    // proves no handoff can match; missing or unparseable rows still scan.
    let live_type = crate::ports::EntityStoreRead::port_entity_with_raw(store, txn, id, |raw| {
        Ok(crate::batch::EntityMetadataHeader::parse(raw).map(|header| header.entity_type))
    })?;
    if matches!(live_type, Some(Some(t)) if t != crate::registry::ENTITY_TYPE_ASSET) {
        return Ok(());
    }
    let mut settled = Vec::new();
    for row in HANDOFFS.iter_from(store, &*txn, &[])? {
        let Ok((key, handoff)) = row else {
            continue;
        };
        if handoff.evidence == *id && handoff.result.is_some() && handoff.erased_at.is_none() {
            settled.push((key, handoff));
        }
    }
    if settled.is_empty() {
        return Ok(());
    }
    let now = store.clock.now_recorded_at();
    for (key, mut handoff) in settled {
        handoff.erased_at = Some(now);
        handoff.work = None;
        HANDOFFS.put(store, txn, &key, &handoff)?;
    }
    Ok(())
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
