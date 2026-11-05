//! Core half of `store::checkpoint_payload::retirement`: its store-layer items live in `oneiron_store::checkpoint_payload::retirement` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::checkpoint_payload::retirement::*;

use super::instance::{self, Lifecycle, PayloadInstance};
use super::kept::KeptGenerations;
use super::{CHECKPOINT_PAYLOADS_ENABLED, PayloadItem, Subtype, corrupt};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::store::key_custody::{
    CustodyKind, RetireCause, RetirementIntent, retirements_in_txn, stage_retirement_in_txn,
};
use heed::{RoTxn, RwTxn};

/// Settles every incarnation whose item starts with `subtype` and
/// `owner_prefix` by `disposition`, in `wtxn`, the deletion's own
/// transaction: how many incarnations it found. `owner_prefix` is a whole
/// owner, or its holding record's id for an attachment occurrence, whose
/// owner bytes start with it.
///
/// # Errors
///
/// Storage faults, and an incarnation row that does not decode.
pub(crate) fn settle_owner_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    subtype: Subtype,
    owner_prefix: &[u8],
    disposition: PayloadDisposition,
) -> Result<usize> {
    if !CHECKPOINT_PAYLOADS_ENABLED {
        return Ok(0);
    }
    let instances = instance::owner_instances_in_txn(store, wtxn, subtype, owner_prefix)?;
    settle_instances_in_txn(store, wtxn, &instances, disposition)?;
    Ok(instances.len())
}

/// [`settle_owner_in_txn`] for `instances`, already read in `wtxn`.
fn settle_instances_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    instances: &[PayloadInstance],
    disposition: PayloadDisposition,
) -> Result<()> {
    for found in instances {
        match disposition {
            PayloadDisposition::Retain => {
                instance::retain_in_txn(store, wtxn, &found.item)?;
            }
            // An incarnation an earlier erase took staged its intent then,
            // in the same transaction; staging it again would journal a
            // second retirement of one leaf.
            PayloadDisposition::Erase if found.lifecycle == Lifecycle::Erased => {}
            PayloadDisposition::Erase => {
                if let Some(generation) = instance::erase_in_txn(store, wtxn, &found.item)? {
                    stage_erase_in_txn(store, wtxn, &found.item, generation)?;
                }
            }
        }
    }
    Ok(())
}

/// Stages the retirement of `item`'s leaf through `generation` in `wtxn`, an
/// erase's intent, raised to the newest generation custody holds for it (a
/// writer that minted a later one and aborted). Nothing for a vault that
/// never bound custody: no leaf was ever minted there. A custody directory
/// that does not list stages the instance's own generation and warns: the
/// erase never fails on custody (Engine 10-20 08:4x, ruling 2).
fn stage_erase_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    item: &PayloadItem,
    generation: u64,
) -> Result<()> {
    let Some(custody) = store.core.key_custody.local() else {
        return Ok(());
    };
    let subject = item.subject(custody.binding())?;
    let newest = custody.newest_generation(&subject).unwrap_or_else(|error| {
        tracing::warn!(
            error = %error,
            "checkpoint payload custody did not list; its erase stages the instance generation"
        );
        None
    });
    let through = newest.map_or(generation, |newest| newest.max(generation));
    stage_retirement_in_txn(
        store,
        wtxn,
        &RetirementIntent {
            subject,
            through,
            cause: RetireCause::Erase,
        },
    )
}

/// The checkpoint payload client's rule for custody's finisher: an erase's
/// leaf retires once no standing legal hold names its owner's record; a
/// retention's once the kept inventory `kept` no longer needs it. A deferral
/// delays only the key. An intent whose incarnation is not erased is damage
/// and is refused by name.
fn ready_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    intent: &RetirementIntent,
    kept: Option<&KeptGenerations>,
) -> Result<bool> {
    let item = PayloadItem::decode(intent.subject.item()).ok_or_else(corrupt)?;
    if let Some(record) = held_record(&item)
        && crate::store::legal_hold::held_in_txn(store, txn, &record)?
    {
        return Ok(false);
    }
    match intent.cause {
        RetireCause::Retention => Ok(kept_inventory_releases(&item, intent.through, kept)),
        RetireCause::Erase => {
            // A history purge's intent retires only generations its live
            // incarnation has left behind (FIX 11800).
            if instance::instance_in_txn(store, txn, &item)?.is_some_and(|found| {
                found.lifecycle != Lifecycle::Erased && intent.through >= found.generation
            }) {
                return Err(Error::CorruptedIndex(
                    "a retiring checkpoint payload leaf is not erased",
                ));
            }
            Ok(true)
        }
    }
}

impl Store {
    /// Carries out every staged checkpoint payload leaf retirement, an
    /// interrupted process's included, in custody's finisher order (marker,
    /// unlink, directory sync, then the handoff to the custody journal):
    /// whether any was owed.
    ///
    /// # Errors
    ///
    /// An archived vault with a retirement standing, an intent this client
    /// refuses by name, and custody faults: the next pass retries.
    pub(crate) fn finish_checkpoint_payload_retirements(&self) -> Result<bool> {
        self.finish_checkpoint_payload_retirements_kept(None)
    }

    /// [`Self::finish_checkpoint_payload_retirements`] with `kept`, the
    /// inventory of every copy a host keeps (KS7-5): a retention's leaf also
    /// retires once no kept copy names a generation at or below it.
    ///
    /// # Errors
    ///
    /// As [`Self::finish_checkpoint_payload_retirements`].
    pub(crate) fn finish_checkpoint_payload_retention(
        &self,
        kept: &KeptGenerations,
    ) -> Result<bool> {
        self.finish_checkpoint_payload_retirements_kept(Some(kept))
    }

    fn finish_checkpoint_payload_retirements_kept(
        &self,
        kept: Option<&KeptGenerations>,
    ) -> Result<bool> {
        if !CHECKPOINT_PAYLOADS_ENABLED {
            return Ok(false);
        }
        // A history purge's left-behind leaf is staged once a kept copy
        // shows its reseal landed (FIX 11800).
        if let Some(kept) = kept {
            instance::stage_resealed_purges(self, kept)?;
        }
        let txn = self.env.read_txn()?;
        let owed = !retirements_in_txn(self, &txn, CustodyKind::CheckpointPayload)?.is_empty();
        drop(txn);
        if owed {
            self.finish_custody_retirements(CustodyKind::CheckpointPayload, |txn, intent| {
                ready_in_txn(self, txn, intent, kept)
            })?;
        }
        Ok(owed)
    }

    /// Post-commit door for a deletion that staged checkpoint payload leaf
    /// retirements. The intents are durable, so a failure here is a warning,
    /// retried by the next housekeeping pass, and never a failure of the
    /// deletion that already committed.
    pub(crate) fn finish_checkpoint_payload_retirements_after_commit(&self) {
        if let Err(error) = self.finish_checkpoint_payload_retirements() {
            tracing::warn!(
                error = %error,
                "checkpoint payload key retirement deferred to the next housekeeping pass"
            );
        }
    }
}
