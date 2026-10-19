//! Body instance retirement (KS-2A, FIX 5683 part A; ARCH-0038
//! #erase-checkpoint-bodies): a delete keeps an instance's key, so the
//! restore window stays; an erase retires it.
//!
//! An erase stages a [`RetireCause::Erase`] intent in its own transaction,
//! for each instance it releases the last holder of, before its owner's
//! rows go: no later collector or restore can lose the cause. An instance
//! another holder still holds keeps its key (shared bytes outlive one
//! owner, ERASE-SHARED = B), and the erase's cause waits on it
//! ([`ERASE_PENDING`]) until whichever release frees its last holder,
//! which stages the intent in its own transaction. Refcounts, holds and
//! reader pins stay as they were; GC is never an erase, and no other
//! holder's instance is ever retired. The finisher destroys a key only
//! once no instance row and no inline binding names it, so the collector
//! has taken its file first, past every reader's pin.

use heed::{RoTxn, RwTxn};

use super::custody::{instance_id, instance_of};
use super::rows::BODY_KEYS;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable, SideTableDbs};
use crate::store::key_custody::{
    CustodyKind, RetireCause, RetirementIntent, stage_retirement_in_txn,
};
use crate::store::{ManifestDbs, Store};

/// Instances an erase of one holder owes a retirement once their last
/// holder releases them, with the digest they hold.
pub(super) const ERASE_PENDING: SideTable<[u8; 16], [u8; 32], Raw> =
    SideTable::new(&side_table::PROVENANCE_BODY_ERASE);

/// Each instance an owner's erase retired or owes, for its receipt.
const ERASED: SideTable<(EntityId, [u8; 16]), Vec<u8>, Raw> =
    SideTable::new(&side_table::PROVENANCE_BODY_ERASED);

/// An inline ASSET body's instance, by its entity.
pub(crate) const INLINE_ASSETS: SideTable<EntityId, [u8; 16], Raw> =
    SideTable::new(&side_table::PROVENANCE_BODY_INLINE);

/// The raw-output rows, keyed by content handle: an erased inline result's
/// bytes go with its last holder. Only presence and removal are read here.
const RAW_OUTPUT_ROWS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::CODE_RUN_RAW_OUTPUT);

/// A result row's first byte when its body rests in it (`code_run`'s
/// stored-body codec).
const STORED_INLINE: u8 = 0;

/// Stages the erase of `instance` in `wtxn` and notes it for `owner`'s
/// receipt.
fn stage_erase<D: ManifestDbs + SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
    owner: Option<&EntityId>,
    instance: &[u8; 16],
) -> Result<()> {
    let Some(custody) = dbs.key_custody().local() else {
        // No instance was ever published here: nothing to retire.
        return Ok(());
    };
    let id = instance_id(custody.binding(), instance)?;
    stage_retirement_in_txn(
        dbs,
        wtxn,
        &RetirementIntent {
            subject: id.subject().clone(),
            through: id.generation(),
            cause: RetireCause::Erase,
        },
    )?;
    if let Some(owner) = owner {
        ERASED.put(dbs, wtxn, &(*owner, *instance), &Vec::new())?;
    }
    Ok(())
}

/// The erase of `owner`'s bodies, in the erase's own transaction, after its
/// provenance released the descriptors of `held` (each digest the owner's
/// bodies held, read before): every instance whose last holder this erase
/// released retires; one another holder still holds owes its retirement
/// to that holder's release. An inline result's row goes with its last
/// holder, so its bytes leave the live vault too. `owner`'s inline ASSET
/// instance retires, its binding with it.
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn erase_bodies_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    owner: &EntityId,
    held: &[[u8; 32]],
) -> Result<()> {
    for digest in held {
        let row = BODY_KEYS.get(store, wtxn, digest)?;
        if crate::provenance::body::digest_is_held_in_txn(store, wtxn, digest)? {
            if let Some(row) = row {
                ERASE_PENDING.put(store, wtxn, &row.instance, digest)?;
                ERASED.put(store, wtxn, &(*owner, row.instance), &Vec::new())?;
            }
            continue;
        }
        // The last holder's inline result goes with it, bound or not, so no
        // later checkpoint carries its bytes.
        drop_inline_result_in_txn(store, wtxn, digest)?;
        if let Some(row) = row {
            ERASE_PENDING.delete(store, wtxn, &row.instance)?;
            stage_erase(store, wtxn, Some(owner), &row.instance)?;
        }
    }
    if let Some(instance) = INLINE_ASSETS.get(store, wtxn, owner)? {
        INLINE_ASSETS.delete(store, wtxn, owner)?;
        stage_erase(store, wtxn, Some(owner), &instance)?;
    }
    Ok(())
}

/// The content handle of the result body `digest`.
fn inline_handle(digest: &[u8; 32]) -> String {
    crate::code_run::CodeRunRawOutput::of_ref(crate::compaction::output::OutputRef {
        hash: *digest,
        byte_len: 0,
    })
    .handle
}

/// The final release of `digest`'s last holder, by any door, in its
/// transaction: when an erase of an earlier holder owes its instance a
/// retirement, the intent is staged now, and an inline result's row goes
/// with it. Nothing else: a delete or a collection keeps the key.
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn release_body_in_txn<D: ManifestDbs + SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
    digest: &[u8; 32],
) -> Result<()> {
    let Some(row) = BODY_KEYS.get(dbs, wtxn, digest)? else {
        return Ok(());
    };
    if !ERASE_PENDING.delete(dbs, wtxn, &row.instance)? {
        return Ok(());
    }
    drop_inline_result_in_txn(dbs, wtxn, digest)?;
    stage_erase(dbs, wtxn, None, &row.instance)
}

/// Drops the inline result row of `digest`, and its instance row, when the
/// body rests inline: an erased body's bytes leave the live vault with its
/// last holder. A file's go with the collector.
fn drop_inline_result_in_txn<D: ManifestDbs + SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
    digest: &[u8; 32],
) -> Result<()> {
    let handle = inline_handle(digest);
    if RAW_OUTPUT_ROWS
        .get(dbs, wtxn, &handle)?
        .is_some_and(|raw| raw.first() == Some(&STORED_INLINE))
    {
        RAW_OUTPUT_ROWS.delete(dbs, wtxn, &handle)?;
        if BODY_KEYS
            .get(dbs, wtxn, digest)?
            .is_some_and(|row| row.inline)
        {
            BODY_KEYS.delete(dbs, wtxn, digest)?;
        }
    }
    Ok(())
}

/// The body client's readiness for one retirement: no instance row and no
/// inline binding names the instance any longer, so no live ciphertext,
/// refcount or row needs its key, and the collector has taken its file past
/// every reader's pin. A retirement still waiting on a holder defers.
fn ready_in_txn(store: &Store, txn: &RoTxn<'_>, intent: &RetirementIntent) -> Result<bool> {
    let Some(instance) = instance_of(&intent.subject.at(0)) else {
        return Ok(false);
    };
    if ERASE_PENDING.contains(store, txn, &instance)? {
        return Ok(false);
    }
    for row in BODY_KEYS.iter_from(store, txn, &[])? {
        if row?.1.instance == instance {
            return Ok(false);
        }
    }
    for row in INLINE_ASSETS.iter_from(store, txn, &[])? {
        if row?.1 == instance {
            return Ok(false);
        }
    }
    Ok(true)
}

impl Store {
    /// Carries out every body instance retirement whose instance nothing
    /// names any longer (KS-2A): the custody finisher's order, marker, unlink
    /// and directory sync, then the handoff to the custody journal.
    ///
    /// # Errors
    ///
    /// Storage and custody errors.
    pub(crate) fn finish_body_custody_retirements(&self) -> Result<()> {
        self.finish_custody_retirements(CustodyKind::BodyInstance, |txn, intent| {
            ready_in_txn(self, txn, intent)
        })
    }

    /// The body instances `owner`'s erase retired or owes.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn erased_body_instances_in_txn(
        &self,
        txn: &RoTxn<'_>,
        owner: &EntityId,
    ) -> Result<Vec<[u8; 16]>> {
        Ok(ERASED
            .scan_keys(self, txn, owner.as_bytes())?
            .into_iter()
            .map(|(_, instance)| instance)
            .collect())
    }

    /// Whether an erase still waits for another holder to release
    /// `instance`.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn body_erase_waits_on_holder_in_txn(
        &self,
        txn: &RoTxn<'_>,
        instance: &[u8; 16],
    ) -> Result<bool> {
        ERASE_PENDING.contains(self, txn, instance)
    }
}
