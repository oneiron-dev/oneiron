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
use super::rows::{BODY_INSTANCES, BODY_KEYS, remembered_body_instances_in_txn};
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
/// bytes go with its last holder. Only presence and removal are read here;
/// the row's codec stays with `code_run`.
const RAW_OUTPUT_ROWS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::CODE_RUN_RAW_OUTPUT);

/// The erased rows one erase writer notes, journaled in custody before it
/// commits (FIX 6229, 7470), so a restore of an image older than the erase
/// still knows whose erase retired each instance.
#[derive(Default)]
pub(super) struct ErasedNotes(Vec<(Vec<u8>, Vec<u8>)>);

impl ErasedNotes {
    /// Notes `instance` for `owner`'s receipt in `wtxn`.
    pub(super) fn note(
        &mut self,
        dbs: &impl SideTableDbs,
        wtxn: &mut RwTxn<'_>,
        owner: &EntityId,
        instance: &[u8; 16],
    ) -> Result<()> {
        let key = (*owner, *instance);
        ERASED.put(dbs, wtxn, &key, &Vec::new())?;
        self.0.push((ERASED.key_bytes(&key), Vec::new()));
        Ok(())
    }

    /// Journals the notes, one frame, before the writer commits.
    pub(super) fn journal<D: ManifestDbs>(self, dbs: &D) -> Result<()> {
        dbs.key_custody().journal_body_history(self.0)
    }
}

/// Stages the erase of `instance` in `wtxn` and notes it for `owner`'s
/// receipt in `notes`.
pub(super) fn stage_erase<D: ManifestDbs + SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
    (owner, notes): (Option<&EntityId>, &mut ErasedNotes),
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
        notes.note(dbs, wtxn, owner, instance)?;
    }
    Ok(())
}

/// Every instance the body `digest` is or was bound under in `txn` (FIX
/// 6023): its row's, then each one remembered, a vault row's only.
fn digest_instances_in_txn<D: SideTableDbs>(
    dbs: &D,
    txn: &RoTxn<'_>,
    digest: &[u8; 32],
) -> Result<Vec<[u8; 16]>> {
    let mut instances = remembered_body_instances_in_txn(dbs, txn, digest)?;
    if let Some(row) = BODY_KEYS.get(dbs, txn, digest)?
        && row.is_vault()
        && !instances.contains(&row.instance)
    {
        instances.insert(0, row.instance);
    }
    Ok(instances)
}

/// Drops the remembered `instances` of `digest`, each retired now.
fn forget_remembered_in_txn<D: SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
    digest: &[u8; 32],
    instances: &[[u8; 16]],
) -> Result<()> {
    for instance in instances {
        BODY_INSTANCES.delete(dbs, wtxn, &(*digest, *instance))?;
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
    erase_bodies_for_owner_in_txn(store, wtxn, owner, owner, held, false)
}

/// [`erase_bodies_in_txn`] when the erase and the body are two rows' (FIX
/// 6225): `erase_owner`'s erase, whose receipt names each instance, reaches
/// the bodies `held` and the inline ASSET instance of `body_owner` (a step
/// claim's erase, its response version's ASSET). `retain_inline`: another
/// holder still keeps that ASSET, so its instance keeps its key and binding
/// and the erase owes its retirement, as a file another descriptor holds
/// does, until that ASSET's final teardown ([`settle_inline_asset_in_txn`]).
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn erase_bodies_for_owner_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    erase_owner: &EntityId,
    body_owner: &EntityId,
    held: &[[u8; 32]],
    retain_inline: bool,
) -> Result<()> {
    let mut notes = ErasedNotes::default();
    for digest in held {
        // Every instance the digest was bound under, so an inline/file
        // switch or a release leaves no older image's copy behind (FIX 6023).
        let instances = digest_instances_in_txn(store, wtxn, digest)?;
        if crate::provenance::body::digest_is_held_in_txn(store, wtxn, digest)? {
            for instance in &instances {
                ERASE_PENDING.put(store, wtxn, instance, digest)?;
                notes.note(store, wtxn, erase_owner, instance)?;
            }
            continue;
        }
        // The last holder's inline result goes with it, bound or not, so no
        // later checkpoint carries its bytes.
        drop_inline_result_in_txn(store, wtxn, digest)?;
        for instance in &instances {
            ERASE_PENDING.delete(store, wtxn, instance)?;
            stage_erase(store, wtxn, (Some(erase_owner), &mut notes), instance)?;
        }
        forget_remembered_in_txn(store, wtxn, digest, &instances)?;
    }
    let Some(instance) = INLINE_ASSETS.get(store, wtxn, body_owner)? else {
        return notes.journal(store);
    };
    if retain_inline {
        // The digest an inline ASSET holds is its row body's: its content
        // hash.
        let digest = crate::ports::EntityStoreRead::port_entity_raw(store, wtxn, body_owner)?
            .and_then(|raw| {
                raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                    .map(|body| *blake3::hash(body).as_bytes())
            })
            .unwrap_or_default();
        ERASE_PENDING.put(store, wtxn, &instance, &digest)?;
        notes.note(store, wtxn, erase_owner, &instance)?;
        return notes.journal(store);
    }
    INLINE_ASSETS.delete(store, wtxn, body_owner)?;
    ERASE_PENDING.delete(store, wtxn, &instance)?;
    stage_erase(store, wtxn, (Some(erase_owner), &mut notes), &instance)?;
    notes.journal(store)
}

/// The final teardown of `owner`'s row, by any door, in its transaction:
/// when an erase of an earlier holder owes its inline ASSET instance a
/// retirement (a shared step response's, FIX 6225), the intent is staged
/// now and the binding goes; `erase` notes it for `owner`'s receipt too.
/// Nothing else: a delete keeps the key of an instance no erase owes.
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn settle_inline_asset_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    owner: &EntityId,
    erase: bool,
) -> Result<()> {
    let Some(instance) = INLINE_ASSETS.get(store, wtxn, owner)? else {
        return Ok(());
    };
    if !ERASE_PENDING.delete(store, wtxn, &instance)? {
        return Ok(());
    }
    INLINE_ASSETS.delete(store, wtxn, owner)?;
    let mut notes = ErasedNotes::default();
    stage_erase(store, wtxn, (erase.then_some(owner), &mut notes), &instance)?;
    notes.journal(store)
}

/// After a claim's erase tore down its response version's ASSET: when the
/// inline instance `captured` before the teardown is bound no longer (its
/// settlement staged its retirement), `erase_owner`'s receipt names it too,
/// the final eraser beside the first (FIX 8502). Sharing is unchanged.
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn note_settled_inline_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    erase_owner: &EntityId,
    asset: &EntityId,
    captured: Option<[u8; 16]>,
) -> Result<()> {
    let Some(instance) = captured else {
        return Ok(());
    };
    if INLINE_ASSETS.contains(store, wtxn, asset)? {
        return Ok(());
    }
    let mut notes = ErasedNotes::default();
    notes.note(store, wtxn, erase_owner, &instance)?;
    notes.journal(store)
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
    // Each instance the digest was bound under that an erase owes (FIX
    // 6023): its row's and every one remembered.
    let mut owed = Vec::new();
    for instance in digest_instances_in_txn(dbs, wtxn, digest)? {
        if ERASE_PENDING.delete(dbs, wtxn, &instance)? {
            owed.push(instance);
        }
    }
    if owed.is_empty() {
        return Ok(());
    }
    drop_inline_result_in_txn(dbs, wtxn, digest)?;
    let mut notes = ErasedNotes::default();
    for instance in &owed {
        stage_erase(dbs, wtxn, (None, &mut notes), instance)?;
    }
    forget_remembered_in_txn(dbs, wtxn, digest, &owed)
}

/// Drops the inline result row of `digest`, and its instance row, when the
/// body rests inline: an erased body's bytes leave the live vault with its
/// last holder, whether or not a raw output held it on its own. A file's go
/// with the collector, a raw output's own hold on it lifted and the file
/// queued: no such hold outlasts an erase (FIX 5399b).
fn drop_inline_result_in_txn<D: ManifestDbs + SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
    digest: &[u8; 32],
) -> Result<()> {
    let handle = inline_handle(digest);
    if RAW_OUTPUT_ROWS
        .get(dbs, wtxn, &handle)?
        .is_some_and(|raw| crate::code_run::code_run_row_inline(&raw))
    {
        RAW_OUTPUT_ROWS.delete(dbs, wtxn, &handle)?;
        if BODY_KEYS
            .get(dbs, wtxn, digest)?
            .is_some_and(|row| row.inline)
        {
            BODY_KEYS.delete(dbs, wtxn, digest)?;
        }
    } else {
        crate::code_run::lift_code_run_file_hold_in_txn(dbs, wtxn, digest)?;
    }
    Ok(())
}

/// The body client's readiness for one retirement: no instance row, no
/// inline binding and no row-held response's binding names the instance any
/// longer, so no live ciphertext, refcount or row needs its key, and the
/// collector has taken its file past every reader's pin. A retirement still
/// waiting on a holder defers; so does a Retention one that a lease, a kept
/// copy or a standing hold needs now (FIX 6022), read under the finisher's
/// custody write guard and writer.
fn ready_in_txn(store: &Store, txn: &RoTxn<'_>, intent: &RetirementIntent) -> Result<bool> {
    let Some(instance) = instance_of(&intent.subject.at(0)) else {
        return Ok(false);
    };
    if ERASE_PENDING.contains(store, txn, &instance)?
        || super::response::response_names_instance_in_txn(store, txn, &instance)?
    {
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
    if intent.cause == RetireCause::Retention {
        return super::retention_policy::retention_ready_in_txn(store, txn, &instance);
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
