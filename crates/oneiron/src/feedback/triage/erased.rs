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
    match &handoff.source {
        super::FeedbackTriageHandoffSource::Erased { .. } => Ok(true),
        super::FeedbackTriageHandoffSource::Retained { evidence, .. } => {
            vault.local_hard_delete_marker_exists_in_txn(txn, evidence)
        }
    }
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
    if handoff.erased_at().is_some() {
        return Ok(true);
    }
    if !evidence_erased_in_txn(vault, txn, handoff)? {
        return Ok(false);
    }
    handoff.erase_source(now);
    super::handoff_index::put_handoff_in_txn(&vault.store, txn, key, handoff)?;
    Ok(true)
}

/// Settles every handoff of erased evidence, acknowledged or not, in place.
/// The original key and result stay; revision, evidence and work leave together.
/// Soft deletes and a present, parsed non-ASSET remain no-ops.
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
        if handoff
            .retained()
            .is_ok_and(|(_, evidence)| evidence == *id)
        {
            settled.push((key, handoff));
        }
    }
    if settled.is_empty() {
        return Ok(());
    }
    let now = store.clock.now_recorded_at();
    for (key, mut handoff) in settled {
        handoff.erase_source(now);
        super::handoff_index::put_handoff_in_txn(store, txn, &key, &handoff)?;
    }
    Ok(())
}

/// Refuses a result for `handoff` once its evidence was erased, so the write
/// that would file findings citing the erased ASSET rolls back; the next
/// sweep settles the revision erased.
pub(crate) fn refuse_erased_in_txn(
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

/// Declared scrub: hard erase and authenticated checkpoint restore share it.
pub(crate) fn erase_handoff_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    erase_handoff_in_txn(&vault.store, txn, id)
}

/// The post-marker continuation of the same accepted hard erase. Its exact
/// target, not the presence of some other marker, selects the handoffs.
pub(crate) fn erase_handoff_as_in_txn(
    erase: &mut crate::deletion::ActorErasureWriter<'_, '_>,
) -> Result<()> {
    let (vault, txn, id) = erase.parts();
    erase_handoff_actor_in_txn(vault, txn, &id)
}
