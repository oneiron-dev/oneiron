//! Retiring the body instances nothing needs any longer (KS-2A, FIX 6022,
//! 6228; CALLS BODY_INSTANCE_RETENTION; Engine 10-20; owner KEY STORE = A).
//!
//! A delete keeps an instance's key, so a kept backup restores what it
//! deleted; an erase retires it at once. Between the two, an instance no
//! row names may still be needed: by a writer that minted it and has yet to
//! name it, by a kept checkpoint image or parked archive that carries it, or
//! by a standing hold. [`body_retention_policy`] is the one hook that says
//! when none does: only then is a Retention retirement staged for it, and
//! only then do its historical obligations (each owner's
//! response-to-instance row, each digest's remembered instance) expire with
//! it, through the same hook. There is no age cutoff and no automatic
//! unpin, and uncertainty keeps the key and its obligations: a holder
//! record that does not read, a binding that does not decode, or an
//! instance this host did not mint (a takeover landed it from a head, and
//! its copies' holders stayed with the old host) keeps it. Nothing here
//! refuses an export or a restore. The finisher reads the policy again for
//! a Retention intent under the custody write guard, then the LMDB writer,
//! before any key goes; an erase stays the provenance door's alone.

use std::collections::BTreeSet;

use heed::RoTxn;

use super::custody::instance_of;
use super::retention::{ERASE_PENDING, INLINE_ASSETS};
use super::rows::{BODY_INSTANCES, BODY_KEYS};
use crate::error::Result;
use crate::store::key_custody::{
    CustodyKind, EntryState, LocalCustody, RetireCause, RetirementIntent, retirement_in_txn,
    stage_retirement_in_txn, withdraw_retention_in_txn,
};
use crate::store::{ManifestDbs, Store};

/// How many instances one sweep writer stages.
const SWEEP_PAGE: usize = 512;

/// Why the policy keeps an instance's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeepReason {
    /// A row names it: an instance row, an inline binding or a response
    /// binding.
    LiveUse,
    /// An erase owes it its retirement once another holder releases it.
    ErasePending,
    /// A mint, a reserve or a spill holds it before any row names it.
    Leased,
    /// A kept image or a parked archive carries it.
    KeptCopy,
    /// A standing legal hold keeps every kept copy.
    Hold,
    /// Another host minted it: who holds its copies is not known here.
    NotMintedHere,
}

/// What [`body_retention_policy`] decides for one instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetentionVerdict {
    /// Nothing needs it: a Retention retirement may be staged, and its
    /// obligations expire.
    Shred,
    /// Its key stays, with every obligation that names it.
    Keep(KeepReason),
}

/// What the policy decides on from the vault's rows, read again in each
/// writer.
pub(crate) struct RetentionContext {
    named: BTreeSet<[u8; 16]>,
    owed: BTreeSet<[u8; 16]>,
    hold: bool,
}

/// What the policy decides on from custody, read once per pass: every
/// instance a kept copy's holder record names, and every one this host
/// minted. A holder registered after the read is the finisher's to see.
pub(crate) struct RetentionHolders {
    kept: BTreeSet<[u8; 16]>,
    minted_here: BTreeSet<[u8; 16]>,
}

/// CALLS "BODY_INSTANCE_RETENTION": the one policy for both a Retention
/// shred of a body instance (FIX 6022) and the expiry of its historical
/// obligations (FIX 6228). It shreds only an instance no row names, no
/// erase owes, no lease holds, no kept copy carries, no standing hold
/// keeps, and that this host minted; anything else keeps it.
pub(crate) fn body_retention_policy(
    context: &RetentionContext,
    holders: &RetentionHolders,
    instance: &[u8; 16],
    leased: bool,
) -> RetentionVerdict {
    let keep = if context.hold {
        KeepReason::Hold
    } else if context.named.contains(instance) {
        KeepReason::LiveUse
    } else if context.owed.contains(instance) {
        KeepReason::ErasePending
    } else if leased {
        KeepReason::Leased
    } else if holders.kept.contains(instance) {
        KeepReason::KeptCopy
    } else if !holders.minted_here.contains(instance) {
        KeepReason::NotMintedHere
    } else {
        return RetentionVerdict::Shred;
    };
    RetentionVerdict::Keep(keep)
}

impl RetentionHolders {
    /// What `custody` holds now; `None` when any of it does not read: the
    /// pass then retires nothing.
    fn read(custody: &LocalCustody<'_>) -> Option<Self> {
        match (
            custody.kept_image_instances(),
            custody.minted_body_instances(),
        ) {
            (Ok(kept), Ok(minted_here)) => Some(Self { kept, minted_here }),
            (Err(error), _) | (_, Err(error)) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "body retention read no holder evidence; every instance stays"
                );
                None
            }
        }
    }
}

impl RetentionContext {
    /// The evidence `txn` holds now; `None` when a row does not decode.
    fn read(store: &Store, txn: &RoTxn<'_>) -> Result<Option<Self>> {
        let Some(named) = named_in_txn(store, txn)? else {
            return Ok(None);
        };
        Ok(Some(Self {
            named,
            owed: ERASE_PENDING
                .scan_keys(store, txn, &[])?
                .into_iter()
                .collect(),
            hold: crate::store::legal_hold::holds_in_txn(store, txn)?
                .iter()
                .any(|hold| hold.stands()),
        }))
    }
}

/// Every instance a row names in `txn`: `None` when a binding does not
/// decode, so the instance it names is not known.
fn named_in_txn(store: &Store, txn: &RoTxn<'_>) -> Result<Option<BTreeSet<[u8; 16]>>> {
    let mut named = BTreeSet::new();
    for row in BODY_KEYS.iter_from(store, txn, &[])? {
        named.insert(row?.1.instance);
    }
    for row in INLINE_ASSETS.iter_from(store, txn, &[])? {
        named.insert(row?.1);
    }
    match super::response::bound_instances_in_txn(store, txn)? {
        Some(bound) => named.extend(bound),
        None => return Ok(None),
    }
    Ok(Some(named))
}

/// Whether a Retention intent for `instance` may still run, read again by
/// the finisher under the custody write guard and the LMDB writer: no lease,
/// kept copy or standing hold needs it now. Its live uses the caller reads.
pub(super) fn retention_ready_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    instance: &[u8; 16],
) -> Result<bool> {
    let Some(custody) = store.core.key_custody.local() else {
        return Ok(false);
    };
    if store.core.key_custody.body_leased(instance)
        || crate::store::legal_hold::holds_in_txn(store, txn)?
            .iter()
            .any(|hold| hold.stands())
    {
        return Ok(false);
    }
    Ok(custody
        .kept_image_instances()
        .is_ok_and(|kept| !kept.contains(instance)))
}

impl Store {
    /// One retention pass over this vault's body instances (FIX 6022,
    /// 6228): every live instance custody holds is put to
    /// [`body_retention_policy`], a page at a time, each page in its own
    /// writer that reads the evidence again. An eligible one has a
    /// Retention retirement staged and its obligations dropped with it; a
    /// standing Retention intent the policy would keep now is withdrawn.
    /// Returns how many it staged. An archived vault, or one with no
    /// custody yet, retires nothing.
    ///
    /// # Errors
    ///
    /// Storage and custody errors.
    pub(crate) fn sweep_body_retention(&self) -> Result<usize> {
        if self.gate_custody_archived() {
            return Ok(0);
        }
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(0);
        };
        let live: Vec<[u8; 16]> = custody
            .census()?
            .into_iter()
            .filter(|(id, state)| {
                id.kind() == CustodyKind::BodyInstance && *state == EntryState::Live
            })
            .filter_map(|(id, _)| instance_of(&id))
            .collect();
        let Some(holders) = RetentionHolders::read(&custody) else {
            return Ok(0);
        };
        let mut staged = 0;
        for page in live.chunks(SWEEP_PAGE) {
            let mut wtxn = self.env.write_txn()?;
            let Some(context) = RetentionContext::read(self, &wtxn)? else {
                return Ok(staged);
            };
            let mut shred = BTreeSet::new();
            for instance in page {
                let leased = self.core.key_custody.body_leased(instance);
                let id = super::instance_id(custody.binding(), instance)?;
                match body_retention_policy(&context, &holders, instance, leased) {
                    RetentionVerdict::Shred => {
                        stage_retirement_in_txn(
                            self,
                            &mut wtxn,
                            &RetirementIntent {
                                subject: id.subject().clone(),
                                through: id.generation(),
                                cause: RetireCause::Retention,
                            },
                        )?;
                        shred.insert(*instance);
                    }
                    RetentionVerdict::Keep(reason) => {
                        tracing::trace!(?reason, "a body instance stays kept");
                        if retirement_in_txn(self, &wtxn, id.subject())?.is_some() {
                            withdraw_retention_in_txn(self, &mut wtxn, id.subject())?;
                        }
                    }
                }
            }
            // Their historical obligations expire through the same hook: no
            // image, hold or holder needs them (FIX 6228).
            super::response::forget_obligations_in_txn(self, &mut wtxn, &shred)?;
            forget_remembered_in_txn(self, &mut wtxn, &shred)?;
            wtxn.commit()?;
            staged += shred.len();
        }
        Ok(staged)
    }
}

/// Drops every remembered digest instance among `instances`.
fn forget_remembered_in_txn<D: ManifestDbs + crate::side_table::SideTableDbs>(
    dbs: &D,
    wtxn: &mut heed::RwTxn<'_>,
    instances: &BTreeSet<[u8; 16]>,
) -> Result<()> {
    if instances.is_empty() {
        return Ok(());
    }
    let mut gone = Vec::new();
    for row in BODY_INSTANCES.iter_raw_from(dbs, wtxn, &[])? {
        let (key, _) = row?;
        if let Some((digest, instance)) =
            <([u8; 32], [u8; 16]) as crate::side_table::SideKey>::decode_key(&key)
            && instances.contains(&instance)
        {
            gone.push((digest, instance));
        }
    }
    for key in gone {
        BODY_INSTANCES.delete(dbs, wtxn, &key)?;
    }
    Ok(())
}

/// What a kept copy's custodian names it by once it landed at `path`: a
/// digest of its absolute path, never its bytes.
fn copy_at(path: &std::path::Path) -> Result<[u8; 32]> {
    let path = std::path::absolute(path)?;
    Ok(blake3::derive_key(
        "oneiron/body-kept-copy/path/v1",
        path.as_os_str().as_encoded_bytes(),
    ))
}

impl Store {
    /// Registers a holder of every body instance the image rows
    /// `vault_meta` carry, synced, before the image is written (FIX 6022):
    /// no retention retires one while the image is kept. `None` when it
    /// carries none, or the vault binds no custody yet.
    ///
    /// # Errors
    ///
    /// Custody faults, and a row that does not decode.
    pub(crate) fn hold_image_bodies(
        &self,
        vault_meta: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<Option<crate::store::key_custody::ImageHolder>> {
        let instances = super::body_instances_in_rows(vault_meta)?;
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(None);
        };
        if instances.is_empty() {
            return Ok(None);
        }
        custody.hold_image_instances(&instances).map(Some)
    }

    /// Registers a holder of every body instance this vault's own rows name,
    /// before a swap parks it as an archive (FIX 6022): its rows and files
    /// keep them until the archive's custodian releases it.
    ///
    /// # Errors
    ///
    /// Storage and custody errors, and a row that does not decode.
    pub(crate) fn hold_parked_archive_bodies(&self) -> Result<()> {
        let named = {
            let txn = self.env.read_txn()?;
            named_in_txn(self, &txn)?
        };
        let named = named.ok_or(crate::Error::CorruptedIndex("body response binding"))?;
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(());
        };
        if !named.is_empty() {
            custody.hold_image_instances(&named)?;
        }
        Ok(())
    }
}

impl crate::Vault {
    /// Names the kept copy of the backup image `image_digest` (hex, its
    /// checkpoint id) by the path it landed at (FIX 6022): what
    /// [`Self::release_backup_copy`] finds its holder by. `false` when no
    /// holder names the image, which keeps whatever another holds.
    ///
    /// # Errors
    ///
    /// Custody faults, and a digest that is not 32 bytes of hex.
    pub fn name_backup_copy(&self, image_digest: &str, path: &std::path::Path) -> Result<bool> {
        let image = blake3::Hash::from_hex(image_digest).map_err(|_| {
            crate::Error::InvalidConfig("a backup's checkpoint id is not hex".into())
        })?;
        let Some(custody) = self.store.core.key_custody.local() else {
            return Ok(false);
        };
        custody.rename_image_copy(image.as_bytes(), &copy_at(path)?)
    }

    /// Releases the local holder of the backup copy that landed at `path`,
    /// once its custodian unlinked it and synced its directory (FIX 6022,
    /// 7060): the instances only it kept may then retire by retention. A
    /// copy no holder names releases nothing; a remote copy is its own
    /// custodian's to release, never this one's.
    ///
    /// # Errors
    ///
    /// Custody faults.
    pub fn release_backup_copy(&self, path: &std::path::Path) -> Result<bool> {
        let Some(custody) = self.store.core.key_custody.local() else {
            return Ok(false);
        };
        custody.release_image_copy(&copy_at(path)?)
    }

    /// [`Store::sweep_body_retention`], then the finisher: post-commit and
    /// warning-only, so a fault is retried by the next pass and fails
    /// nothing that committed.
    pub(crate) fn sweep_body_retention_after_commit(&self) {
        match self.store.sweep_body_retention() {
            Ok(0) => {}
            Ok(_) => self.finish_body_custody_retirements_after_commit(),
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "body retention deferred to the next pass"
            ),
        }
    }
}
