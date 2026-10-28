//! An owner's activation of an archived vault as a side vault of the vault
//! that replaced it (moved out of the checkpoint custody module whole), with
//! its bodies' prune and read back (KS-2B1, FIX 6020), and its known-value
//! history's (KS-3): required whole through the same plan, an erased
//! holder's references dropped, every kept entry read back under the fork.
//!
//! The archive's body instances fork with its claim keys. What its source
//! retired takes the archive's rows as an erase took the source's, and as a
//! restore takes an image's: each descriptor holding a retired digest goes
//! explicitly incomplete, its holder, release, instance and inline result
//! rows go, an inline ASSET keeps its header-only shell, and a row-held
//! response takes its erased disposition. Every body that stays is then read
//! back under the forked custody before the archive lifts: a sealed file
//! frame by frame, a plain one against its digest with its instance's key
//! read too (a plain read takes none), and an inline body's, an inline
//! ASSET's and a response's instance key.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;
use heed::types::Bytes;

use super::super::ledger::LEDGER;
#[cfg(test)]
use super::BEFORE_ACTIVATION_FORK;
use super::{
    ARCHIVED, ExpectedPadObjects, GATE_DECISION_KEY_PREFIX, GateDecisionId, LiveCustody,
    PadObjectsLanding, Rows, archived_by, corrupt, destination, install_source_pad_objects_in_txn,
    live_custody_prefixes, orcb, preflight_checkpoint_rows, refuse_custody_beside,
    replace_host_holds_in_txn, vault_meta_rows,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EntityStoreMaintenance, ScrubbedRecord};
use crate::side_table::{self, SideKey, SideTableDbs};
use crate::store::key_custody::{self, CustodyBinding, LocalCustody};
use crate::store::{
    BODY_KEYS, BodyKeyRow, INLINE_ASSETS, RESPONSE_BINDINGS, ResponseBinding, ResponseFamily,
    Store, body_instances_in_rows, body_key_in, carrier_row, known_history_prefixes,
    prune_retired_bodies_in_rows, read_back_known_history, require_body_instances,
    require_known_history,
};

/// The `vault_meta` families a body prune reads and writes: the instance
/// rows and bindings, and the descriptors with their holder and release
/// rows.
fn body_prefixes() -> [&'static [u8]; 6] {
    [
        BODY_KEYS.decl().prefix,
        INLINE_ASSETS.decl().prefix,
        RESPONSE_BINDINGS.decl().prefix,
        side_table::PROVENANCE_BODY.prefix,
        side_table::PROVENANCE_BODY_DIGEST.prefix,
        side_table::PROVENANCE_BODY_RELEASED.prefix,
    ]
}

/// What an activation's prune changes in the archive: the `vault_meta` rows
/// it deletes and the ones it rewrites, the files it queues for the
/// collector, the inline ASSETs it shells and the row-held responses it
/// leaves their erased disposition.
struct ArchivePrune {
    deleted: BTreeSet<Vec<u8>>,
    rewritten: Vec<(Vec<u8>, Vec<u8>)>,
    /// Each retired body file, queued for the collector.
    files: Vec<[u8; 32]>,
    assets: BTreeSet<EntityId>,
    /// Each retired response's carrier, with the instance it was bound to.
    responses: BTreeMap<Vec<u8>, [u8; 16]>,
    /// The body rows that stay, read back under the forked custody.
    kept: Rows,
}

impl ArchivePrune {
    /// The prune of the `retired` instances among `kept`, `rows` with the
    /// known-value history it keeps (KS-3), as a restore prunes an image's.
    fn of(rows: &Rows, mut kept: Rows, retired: &BTreeSet<[u8; 16]>) -> Result<Self> {
        let pruned = prune_retired_bodies_in_rows(&mut kept, retired)?;
        let after: BTreeMap<&[u8], &[u8]> = kept
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice()))
            .collect();
        let mut deleted = pruned.row_keys();
        let mut rewritten = Vec::new();
        for (key, value) in rows {
            match after.get(key.as_slice()) {
                None => {
                    deleted.insert(key.clone());
                }
                Some(now) if *now != value.as_slice() => {
                    rewritten.push((key.clone(), now.to_vec()));
                }
                Some(_) => {}
            }
        }
        // A retired file goes to the collector, as any file whose last
        // holder went: a plain one is unlinked by its digest, so no erased
        // body rests on disk in the clear; a sealed one, under a key no
        // custody holds, waits for the orphan sweep.
        let mut files = Vec::new();
        for (key, value) in rows {
            if let Some(digest) = key
                .strip_prefix(BODY_KEYS.decl().prefix)
                .and_then(<[u8; 32]>::decode_key)
                && pruned.digests.contains(&digest)
                && !BODY_KEYS.decode_value(value)?.inline
            {
                files.push(digest);
            }
        }
        Ok(Self {
            deleted,
            rewritten,
            files,
            assets: pruned.assets,
            responses: pruned.responses,
            kept,
        })
    }
}

impl Store {
    /// An owner's activation of this archived vault as a side vault of the
    /// vault whose live custody state is `source`, the one that replaced it.
    /// Its custody forks as a side restore's does, into a directory of its
    /// own beside its root: every receipt it holds is checked against the
    /// custody it binds to first, a key `source` destroyed or has committed
    /// to destroy is not copied and the receipts under it are dropped, every
    /// receipt it keeps is read back under the forked keys, and so is every
    /// body it keeps, once what `source` retired took its rows (FIX 6020).
    /// Only then does the new binding commit, with the archive mark lifted
    /// and this install's machine identity dropped, the replacement keeping
    /// it. Anything short of that leaves it archived, as it was. The caller
    /// reopens the vault, whose handles then shred only its own keys.
    /// Its world key pads go through the same plan (KS-5, FIX 5686 part 2):
    /// a pad `source` retired takes its row out, never back from the row's
    /// own pad, and a live one forks with the rest. So do its credential
    /// values (KS-6 part 2), each by exact id: one `source` lacks, or one
    /// that does not plan or read back from the forked custody, rests
    /// sealed, pending, never a refusal. Its source's current pad objects,
    /// captured with its custody, take the place of its own before the
    /// archive lifts, while it still holds `expected`, in a savepoint that
    /// keeps its own on any fault (PAD-1). Returns the claim-bound
    /// decisions dropped because their keys stayed on another host, by id
    /// (hex), as a restore's report names them, the pads erased, the
    /// credentials planned, and what came of the pad objects.
    pub(crate) fn activate_archived(
        &self,
        source: &LiveCustody,
        expected: Option<&ExpectedPadObjects>,
    ) -> Result<(
        Vec<String>,
        Vec<crate::world_keys::WorldKeyId>,
        crate::secret_custody::PlannedCredentials,
        PadObjectsLanding,
    )> {
        let (rows, own_fences) = {
            let txn = self.env.read_txn()?;
            let mark = ARCHIVED.get(self, &txn, &())?;
            if !archived_by(mark.as_deref(), self.env.path())? {
                return Err(Error::InvalidConfig("this vault is not archived".into()));
            }
            let mut prefixes = live_custody_prefixes();
            prefixes.push(GATE_DECISION_KEY_PREFIX);
            prefixes.extend(body_prefixes());
            prefixes.extend(known_history_prefixes());
            let rows = vault_meta_rows(&self.env, &txn, &prefixes)?;
            (rows, self.credential_fences_in_txn(&txn))
        };
        let mut custody = preflight_checkpoint_rows(&rows, Some(source))?;
        // Its body instances fork with its claim keys (KS-2A): a missing one
        // refuses; a retired one's rows go before the archive is lifted.
        let retired = require_body_instances(&body_instances_in_rows(&rows)?, custody.plan_mut())?;
        // So does its known-value history (KS-3), each retained entry by
        // exact id: a missing one refuses by name, an erased holder's
        // references go.
        let mut kept = rows.clone();
        require_known_history(&mut kept, custody.plan_mut())?;
        let prune = ArchivePrune::of(&rows, kept, &retired)?;
        let erased_pads = crate::world_keys::plan_archived_pads(self, custody.plan_mut())?;
        // Its credential values' keys fork with the rest, each by exact id
        // from its source's custody (KS-6 part 2, CALLS `KS-6 required
        // restore set`): one the source lacks, or a custody fault, leaves
        // that row sealed, pending, warned. One its source's erase evidence,
        // its own, or a retired value key of the custody it binds names
        // erased is never forked, and its fence comes with it (CALLS `KS-6
        // erase fence form`), each looked up by its own handle.
        let mut fences = source.credential_fences();
        fences.merge(&own_fences);
        if let Some(binding) = custody.plan_mut().source() {
            fences.with_custody(binding);
        }
        let mut credentials =
            crate::secret_custody::plan_archived_credentials(self, custody.plan_mut(), &mut fences);
        // The environment's path is the canonical root it was opened at.
        let root = self.env.path().to_path_buf();
        refuse_custody_beside(&root)?;
        #[cfg(test)]
        if let Some(callback) = BEFORE_ACTIVATION_FORK.with(|slot| slot.borrow_mut().take()) {
            callback();
        }
        let mut wtxn = self.env.past_seal_write_txn()?;
        let forked = self.fork_gate_custody_to_in_txn(&mut wtxn, &custody, &root)?;
        let mut landing = PadObjectsLanding::NotAttempted;
        let committed = self
            .prune_bodies_in_txn(&mut wtxn, &prune, source)
            .and_then(|()| self.drop_erased_gate_decisions_in_txn(&mut wtxn, custody.erased()))
            .and_then(|()| crate::world_keys::drop_pad_rows_in_txn(self, &mut wtxn, &erased_pads))
            .and_then(|()| self.read_back_in_txn(&wtxn))
            .and_then(|()| self.read_back_bodies_in_txn(&wtxn, &prune.kept))
            .and_then(|()| self.read_back_known_in_txn(&wtxn, &prune.kept))
            .and_then(|()| {
                read_back_credentials_in_txn(self, &wtxn, &mut credentials);
                fences.put_in_txn(self, &mut wtxn)
            })
            .and_then(|()| crate::identity::drop_machine_identity_in_txn(self, &mut wtxn))
            // The orders standing on its source now, not the ones it had.
            .and_then(|()| replace_host_holds_in_txn(self, &mut wtxn, source.host_holds()))
            // Its source's pad objects, before the archive lifts.
            .and_then(|()| {
                landing = install_source_pad_objects_in_txn(
                    self,
                    &mut wtxn,
                    &source.pad_objects,
                    expected,
                );
                Ok(())
            })
            .and_then(|()| ARCHIVED.delete(self, &mut wtxn, &()))
            .and_then(|_| Ok(wtxn.commit()?));
        if let Err(err) = committed {
            if let Some(forked) = forked {
                forked.remove();
            }
            return Err(err);
        }
        let lost = custody.lost().iter().map(|(id, _)| id.to_hex()).collect();
        Ok((
            lost,
            erased_pads.into_iter().map(|(_, key)| key).collect(),
            credentials,
            landing,
        ))
    }

    /// Applies `prune` in `wtxn`: its row deletions and rewrites, each
    /// pruned inline ASSET's shell, and each pruned response's erased
    /// disposition, then the step response pins it leaves (FIX 6225). A
    /// keyed entry its own caller's erase retired goes, as that erase dropped
    /// it live and a cold restore drops it; `source`'s erase receipts say
    /// whose erase retired it (FIX 7470, 9066).
    fn prune_bodies_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        prune: &ArchivePrune,
        source: &LiveCustody,
    ) -> Result<()> {
        // FIX 9180: what the source retired of a replay row's or a step
        // start's parts, read before the prune takes a start's rows and
        // applied once per destination after it.
        let replay = ResponseFamily::replay_prune_in_txn(self, wtxn, &prune.responses)?;
        destination::delete_vault_meta_in_txn(&self.env, wtxn, &prune.deleted)?;
        for (key, value) in &prune.rewritten {
            self.side_vault_meta().put(wtxn, key, value)?;
        }
        for digest in &prune.files {
            crate::provenance::body::queue_pruned_file_in_txn(self, wtxn, digest)?;
        }
        if !prune.assets.is_empty() {
            let at = crate::ports::recorded_at_in_txn(self, wtxn)?;
            for entity in &prune.assets {
                self.port_entity_scrub(wtxn, entity, ScrubbedRecord::Shell, at)?;
            }
        }
        for (carrier, instance) in &prune.responses {
            let Some((db, key)) = carrier_row(carrier) else {
                continue;
            };
            let Some(value) = self
                .env
                .open_database::<Bytes, Bytes>(wtxn, Some(db.name()))?
                .ok_or_else(corrupt)?
                .get(wtxn, key)?
                .map(<[u8]>::to_vec)
            else {
                continue;
            };
            let Some(family) = ResponseFamily::of_row(db, key, &value) else {
                continue;
            };
            let Some((carriage, _)) = family.scan(key, &value).carriage() else {
                continue;
            };
            let caller = (family == ResponseFamily::Http)
                .then(|| carriage.stub.get(..carriage.retired))
                .flatten()
                .and_then(crate::store::http_erase_drop_caller);
            if caller.is_some_and(|caller| source.erased_by(&caller, instance)) {
                let row = std::str::from_utf8(key)
                    .map_err(|_| Error::CorruptedIndex("sync_state row key"))?;
                self.side_sync_state()?.delete(wtxn, row)?;
                continue;
            }
            family.retire_in_txn(self, wtxn, key, &carriage)?;
        }
        replay.apply_in_txn(self, wtxn)?;
        // A step claim whose response's artifact version rests in a body its
        // source retired takes its erased disposition too, and every pin
        // goes with what the archive no longer holds (FIX 6225). The retired
        // ASSETs and files were read off the bindings before they went.
        let files: BTreeSet<[u8; 32]> = prune.files.iter().copied().collect();
        crate::llm::prune_step_response_pins_in_txn(self, wtxn, &prune.assets, &files)
    }

    /// Reads back, under the custody `txn` binds (the forked one), every
    /// body `kept` names: a file whole, through its envelope's frames or
    /// against its digest, and every inline body's, inline ASSET's and
    /// row-held response's instance key.
    fn read_back_bodies_in_txn(&self, txn: &RoTxn<'_>, kept: &Rows) -> Result<()> {
        if body_instances_in_rows(kept)?.is_empty() {
            return Ok(());
        }
        let binding: CustodyBinding =
            key_custody::binding_in_txn(self, txn)?.ok_or_else(corrupt)?;
        let mut dir = None;
        for (key, value) in kept {
            if let Some(digest) = key
                .strip_prefix(BODY_KEYS.decl().prefix)
                .and_then(<[u8; 32]>::decode_key)
            {
                let row: BodyKeyRow = BODY_KEYS.decode_value(value)?;
                if row.inline {
                    body_key_in(&binding, &row.instance)?;
                } else {
                    if dir.is_none() {
                        dir = Some(self.body_dir()?);
                    }
                    dir.as_ref()
                        .ok_or_else(corrupt)?
                        .read_back(&binding, &digest, &row)?;
                }
            } else if key.starts_with(INLINE_ASSETS.decl().prefix) {
                body_key_in(&binding, &INLINE_ASSETS.decode_value(value)?)?;
            } else if key.starts_with(RESPONSE_BINDINGS.decl().prefix) {
                body_key_in(&binding, &ResponseBinding::of_row(value)?.instance)?;
            }
        }
        Ok(())
    }

    /// Reads back, under the custody `txn` binds (the forked one), the
    /// known-value index's master and every history entry `kept` names
    /// (KS-3).
    fn read_back_known_in_txn(&self, txn: &RoTxn<'_>, kept: &Rows) -> Result<()> {
        let prefixes = known_history_prefixes();
        if !kept
            .iter()
            .any(|(key, _)| prefixes.iter().any(|prefix| key.starts_with(prefix)))
        {
            return Ok(());
        }
        let binding: CustodyBinding =
            key_custody::binding_in_txn(self, txn)?.ok_or_else(corrupt)?;
        read_back_known_history(kept, &binding)
    }

    /// Reads every encrypted receipt in `txn` under the custody it binds.
    fn read_back_in_txn(&self, txn: &RoTxn<'_>) -> Result<()> {
        let binding = key_custody::binding_in_txn(self, txn)?;
        for row in LEDGER.iter_raw_from(self, txn, &[])? {
            let (key, raw) = row?;
            if orcb::is_orcb(&raw) {
                let id = GateDecisionId::decode_key(&key)
                    .ok_or(Error::CorruptedIndex("gate decision ledger key"))?;
                let custody = LocalCustody::at(binding.as_ref().ok_or_else(corrupt)?);
                orcb::decode_hot(custody, id, &raw)?;
            }
        }
        Ok(())
    }
}

/// Reads back each credential value `credentials` planned live: its row in
/// `txn` opened under its exact leaf from the custody `txn` binds (the
/// forked one), the bytes wiped at once. One that does not open, or a
/// binding that does not read, leaves it sealed, pending (CALLS `KS-6
/// credential fork fault`), never a refusal.
fn read_back_credentials_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    credentials: &mut crate::secret_custody::PlannedCredentials,
) {
    let binding: Option<CustodyBinding> = key_custody::binding_in_txn(store, txn).ok().flatten();
    credentials.read_back(|credential, generation| {
        binding.as_ref().is_some_and(|binding| {
            crate::secret_custody::stored_value_opens_in_txn(
                store,
                txn,
                credential,
                generation,
                |credential, generation| {
                    crate::store::credential_value_leaf_in(binding, credential, generation)
                },
            )
        })
    });
}
