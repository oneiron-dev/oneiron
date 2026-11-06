//! What an owner's deletion does to its checkpoint payload leaves (KS7-4,
//! FIX 5688).
//!
//! An erase marks every incarnation of the owner erased, an older retained
//! one included, and stages one Erase intent per incarnation through the
//! generation its leaf is at, in the erase's own transaction; custody's one
//! finisher destroys the leaves after the commit, so every old checkpoint
//! holding the owner's bytes keeps them only unreadable. An ordinary delete
//! marks the active incarnation retained and stages nothing: its leaf stays
//! for the checkpoints holding it, for the restore window (ARCH-0038
//! #key-store).
//!
//! Nothing here refuses or waits (Engine 10-20 08:4x, rulings 2 and 3): the
//! user act commits as it does today, and a legal hold, a missing kept
//! inventory or a custody fault delays only the key's retirement, never the
//! delete. While [`CHECKPOINT_PAYLOADS_ENABLED`] is off no instance row
//! exists, so every settle here touches nothing.

use heed::{RoTxn, RwTxn};

use crate::error::{Error, Result};
use crate::store::Store;
use crate::store::key_custody::{
    CustodyKind, RetireCause, RetirementIntent, retirements_in_txn, stage_retirement_in_txn,
};

use super::instance::{self, Lifecycle, PayloadInstance};
use super::kept::KeptGenerations;
use super::{CHECKPOINT_PAYLOADS_ENABLED, PayloadItem, Subtype, corrupt};

/// What an owner's deletion does to its compartments (Engine 10-20 08:4x,
/// ruling 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PayloadDisposition {
    /// An ordinary delete: the leaves stay for the checkpoints holding them,
    /// and nothing new is sealed under the owner's active incarnation.
    Retain,
    /// The owner's erase: every incarnation's leaf retires, so no old
    /// checkpoint opens the owner's bytes again.
    Erase,
}

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

/// The record a legal hold on `item`'s owner names: an entity tree's own id,
/// an attachment occurrence's holding record. A code document or an
/// outbound call names no record a hold can target yet (Engine 10-20 08:4x,
/// ruling 4).
fn held_record(item: &PayloadItem) -> Option<[u8; 16]> {
    match item.subtype() {
        Subtype::EntityTree | Subtype::AttachmentOccurrence => item.owner()[..16].try_into().ok(),
        Subtype::CodeDocument | Subtype::OutboundCall => None,
    }
}

/// The kept-checkpoint inventory's answer for a retention retirement of
/// `item` through `through`: whether no kept checkpoint still needs a
/// generation at or below it. `kept` is the authenticated inventory of every
/// kept manifest (KS7-5), read when a host's prune hands its kept copies
/// over; with none, no retention retirement is ready, and a missing
/// inventory only ever delays a key (Engine 10-20 08:4x, ruling 3).
fn kept_inventory_releases(
    item: &PayloadItem,
    through: u64,
    kept: Option<&KeptGenerations>,
) -> bool {
    kept.is_some_and(|kept| kept.releases(item, through))
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
