//! Opening a restored vault's Locked worlds again (PAD-2, FIX 10470; CALLS
//! C-L04-MANAGED-RESTORE-LOCKED-WORLDS, accepted): the custody head beside
//! the backup a restore landed, opened with the recovery kit or the key of a
//! machine a world admits (DEC-0005; ARCH-0038 KEY STORE = A), gives the
//! pads of each world it left Locked.
//!
//! The backup must be the checkpoint the chosen epoch landed, and its head
//! this vault's current custody lineage, admitted as a restore admits it. No
//! restore, custody route, landing or takeover runs again, and no binding,
//! writer epoch, recipient or authority is replaced: each world's owed pads
//! are installed into the vault's current custody and read back, then each
//! owed reference is re-read in the writer's transaction and rests again
//! with its pad, read back once committed. Worlds land one by one, each on
//! its own; a fault in one is named and the rest go on. The epoch is then
//! reconciled in place ([`super::epochs`]): a world stays Locked until every
//! reference it owes rests or its erase stands. A head that lacks a world's
//! pads leaves it Locked: a kit cannot recreate ciphertext the head never
//! carried. Pad resolution is not readability: every authority and key
//! wrap check still applies to the world's content.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use heed::RwTxn;
use serde::Serialize;
use zeroize::Zeroizing;

use super::{CheckpointKey, CustodyRecovery, PadRestoreNote, epochs, read_image_required};
use crate::consent::AuthenticatedOwner;
use crate::world_keys::{
    PadRowRest, WorldKeyId, pad_row_erased_in_txn, pad_row_rest_in_txn, pad_row_rests_in_txn,
    world_keys_destroyed_in_txn,
};
use crate::{EntityId, Error, ErrorKind, Result, Vault};

/// What a reopen of a restore epoch's Locked worlds did. Public ids and
/// counts alone: never a pad, a key or a secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PadReopenReport {
    /// The restore epoch it reopened, by sequence.
    pub epoch: u64,
    /// The checkpoint that epoch landed, which the backup is.
    pub checkpoint_id: String,
    /// Each world whose owed pads the head gave, installed into current
    /// custody, read back and rested, by hex id.
    pub opened_worlds: Vec<String>,
    /// Pads published into current custody, or found there with the same
    /// bytes, in committed installs.
    pub installed: usize,
    /// Bare references rested again in committed writes.
    pub rested: usize,
    /// References the epoch still owes.
    pub owed_refs: usize,
    /// What the epoch still says of its pads: a world the head did not open
    /// stays Locked, Pending and Withheld stay, and an erase that stands is
    /// ErasedUnavailable.
    pub remaining: Vec<PadRestoreNote>,
    /// Each stage that faulted, by world; what committed before it stands.
    pub faults: Vec<PadReopenFault>,
    /// What the head it used says: rollback is not proven when no custody
    /// anchor is configured.
    pub custody_note: Option<String>,
}

/// One stage of a world's reopen that did not complete.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PadReopenFault {
    /// The world, by hex id; `None` for the epoch's reconciliation.
    pub world: Option<String>,
    pub stage: PadReopenStage,
    /// The error's kind; `None` when the stage committed but what it wrote
    /// did not read back.
    pub error_kind: Option<ErrorKind>,
}

/// The stages a world's reopen goes through, in order, then the epoch's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PadReopenStage {
    Install,
    ReadBack,
    Rest,
    Verify,
    Reconcile,
}

/// What resting one owed reference again came to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RefRest {
    Rested,
    Held,
    Unheld,
    Erased,
}

impl Vault {
    /// Opens the worlds restore epoch `epoch` left Locked with the custody
    /// head beside `backup`, the checkpoint that epoch landed, opened with
    /// `key` (the backup's data key, for the head's control compartment) and
    /// the kit's root or an admitted machine's key `recovery` carries. With
    /// no `epoch`, the latest epoch that landed `backup`'s checkpoint. The
    /// owner's proof is checked first and again in every write. An epoch
    /// that owes no Locked world reports as it stands and opens nothing.
    ///
    /// # Errors
    ///
    /// `owner` no longer holds; no epoch `epoch`, or none that landed
    /// `backup`; a backup that is not its checkpoint, or names no custody
    /// head; a head that is another vault's lineage or that its admission
    /// refuses (seal, chain, anchor, age). Faults after admission are named
    /// in the report, never returned.
    pub fn reopen_restore_pads_as(
        &self,
        owner: &AuthenticatedOwner,
        epoch: Option<u64>,
        backup: &Path,
        key: &CheckpointKey,
        recovery: &CustodyRecovery<'_>,
    ) -> Result<PadReopenReport> {
        {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_in_txn(self, &txn)?;
        }
        let (_, checkpoint_id, _, required) = read_image_required(backup, key)?;
        let (epoch, recorded) = match epoch {
            Some(epoch) => {
                let recorded = epochs::epoch_at(self, epoch)?.ok_or_else(|| {
                    Error::InvalidConfig(format!("this vault recorded no restore epoch {epoch}"))
                })?;
                if checkpoint_id != recorded.checkpoint_id {
                    return Err(Error::InvalidConfig(format!(
                        "backup {} is not the checkpoint restore epoch {epoch} landed",
                        backup.display()
                    )));
                }
                (epoch, recorded)
            }
            None => epochs::latest_epoch_of(self, &checkpoint_id)?.ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "this vault recorded no restore of backup {}",
                    backup.display()
                ))
            })?,
        };
        let mut report = PadReopenReport {
            epoch,
            checkpoint_id: recorded.checkpoint_id.clone(),
            opened_worlds: Vec::new(),
            installed: 0,
            rested: 0,
            owed_refs: recorded.pad_recovery.required_refs.len(),
            remaining: recorded.pad_recovery.remaining.clone(),
            faults: Vec::new(),
            custody_note: None,
        };
        let locked = recorded.pad_recovery.locked_refs();
        if locked.is_empty() {
            return Ok(report);
        }
        let required = required.ok_or_else(|| {
            Error::InvalidConfig("the backup names no custody head to open its pads from".into())
        })?;
        let admitted =
            self.store
                .admit_restore_pads(&required, &recovery.source(), key.custody_wrap())?;
        report.custody_note = admitted.note().map(str::to_owned);
        let mut retired = BTreeSet::new();
        for (world, keys) in &locked {
            let items: BTreeSet<[u8; 40]> = keys.iter().map(WorldKeyId::envelope_key_id).collect();
            let gone = admitted.retired_among(&items);
            let live = admitted.live_among(*world, &items);
            let opened = if live.is_empty() {
                Ok(())
            } else {
                self.reopen_world(owner, *world, keys, &live, &gone, &mut report)
            };
            retired.extend(gone);
            if let Err((stage, error_kind)) = opened {
                report.faults.push(PadReopenFault {
                    world: Some(world.to_hex()),
                    stage,
                    error_kind,
                });
            }
        }
        match self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            epochs::reconcile_restore_pad_notes_in_txn(self, txn, Some(epoch), &retired)
        }) {
            Ok(states) => {
                if let Some(state) = states.get(&epoch) {
                    report.owed_refs = state.required_refs.len();
                    report.remaining = state.remaining.clone();
                }
                // The carried pads (PAD-3) the epoch no longer owes go; one a
                // fault leaves stays carried until the next prune.
                if let Err(error) = epochs::prune_carried_pads(self) {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "carried world pads not pruned after a pad reopen"
                    );
                }
            }
            Err(error) => report.faults.push(PadReopenFault {
                world: None,
                stage: PadReopenStage::Reconcile,
                error_kind: Some(error.kind()),
            }),
        }
        Ok(report)
    }

    /// One world's reopen: its `live` pads installed into current custody
    /// and read back, then its owed references `keys` rested and read back.
    /// `retired` names the pads the head holds retired: their erase stands,
    /// so they are never rested.
    fn reopen_world(
        &self,
        owner: &AuthenticatedOwner,
        world: EntityId,
        keys: &[WorldKeyId],
        live: &BTreeMap<[u8; 40], Zeroizing<[u8; 32]>>,
        retired: &BTreeSet<[u8; 40]>,
        report: &mut PadReopenReport,
    ) -> std::result::Result<(), (PadReopenStage, Option<ErrorKind>)> {
        use PadReopenStage as S;
        let installed = self
            .with_write_txn_grouped(|txn| {
                owner.revalidate_in_txn(self, txn)?;
                self.store
                    .install_world_pads_in_txn(txn, world, live, retired.len())
            })
            .map_err(faulted(S::Install))?;
        report.installed += installed.held.len();
        if !self
            .store
            .read_back_world_pads(live, &installed)
            .map_err(faulted(S::ReadBack))?
        {
            return Err((S::ReadBack, None));
        }
        let rests = self
            .with_write_txn_grouped(|txn| {
                owner.revalidate_in_txn(self, txn)?;
                rest_references_in_txn(self, txn, keys, retired)
            })
            .map_err(faulted(S::Rest))?;
        let rested: Vec<&WorldKeyId> = rests
            .iter()
            .filter(|(_, rest)| *rest == RefRest::Rested)
            .map(|(key, _)| key)
            .collect();
        report.rested += rested.len();
        let txn = self
            .store
            .env
            .read_txn()
            .map_err(|error| faulted(S::Verify)(Error::from(error)))?;
        for key in rested {
            if !pad_row_rests_in_txn(&self.store, &txn, key).map_err(faulted(S::Verify))? {
                return Err((S::Verify, None));
            }
        }
        // Opened only when every owed reference is at rest or erased, and
        // one at least is at rest.
        if rests
            .iter()
            .all(|(_, rest)| !matches!(rest, RefRest::Unheld))
            && rests
                .iter()
                .any(|(_, rest)| matches!(rest, RefRest::Rested | RefRest::Held))
        {
            report.opened_worlds.push(world.to_hex());
        }
        Ok(())
    }
}

/// The fault `stage` names for `error`, by its kind alone.
fn faulted(stage: PadReopenStage) -> impl FnOnce(Error) -> (PadReopenStage, Option<ErrorKind>) {
    move |error| (stage, Some(error.kind()))
}

/// Rests each owed reference of `keys` again in `txn`, the writer's, each
/// row re-read here: one whose world's keys were destroyed or whose row was
/// hard-erased is left as it is, one that holds its pad already stays, and
/// a bare reference whose pad current custody holds rests with it beside
/// its reference (`rested_pad_row`). One the head holds `retired` is left
/// as it is: its erase stands. Never an old image's row.
fn rest_references_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    keys: &[WorldKeyId],
    retired: &BTreeSet<[u8; 40]>,
) -> Result<Vec<(WorldKeyId, RefRest)>> {
    let mut outcomes = Vec::with_capacity(keys.len());
    let mut rows = Vec::new();
    for key in keys {
        if retired.contains(&key.envelope_key_id())
            || world_keys_destroyed_in_txn(&vault.store, txn, key.world)?
            || pad_row_erased_in_txn(&vault.store, txn, &key.envelope_key_id())?
        {
            outcomes.push((*key, RefRest::Erased));
            continue;
        }
        let rest = match pad_row_rest_in_txn(&vault.store, txn, key)? {
            PadRowRest::Rest { row, rested } => {
                rows.push((row, rested));
                RefRest::Rested
            }
            PadRowRest::Held => RefRest::Held,
            PadRowRest::Unheld => RefRest::Unheld,
        };
        outcomes.push((*key, rest));
    }
    let puts: Vec<(&[u8], &[u8])> = rows
        .iter()
        .map(|(row, rested)| (row.as_bytes().as_slice(), rested.as_slice()))
        .collect();
    super::pad_custody::put_rows_in_txn(vault, txn, &puts)?;
    Ok(outcomes)
}
