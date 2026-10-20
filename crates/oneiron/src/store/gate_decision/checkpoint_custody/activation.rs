//! An owner's activation of an archived vault as a side vault of the vault
//! that replaced it (moved out of the checkpoint custody module whole), with
//! its bodies' prune and read back (KS-2B1, FIX 6020).
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
    ARCHIVED, GATE_DECISION_KEY_PREFIX, GateDecisionId, LiveCustody, Rows, archived_by, corrupt,
    destination, live_custody_prefixes, orcb, preflight_checkpoint_rows, refuse_custody_beside,
    replace_host_holds_in_txn, vault_meta_rows,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EntityStoreMaintenance, ScrubbedRecord};
use crate::side_table::{self, SideKey, SideTableDbs};
use crate::store::key_custody::{self, CustodyBinding, LocalCustody};
use crate::store::{
    BODY_KEYS, BodyKeyRow, INLINE_ASSETS, RESPONSE_BINDINGS, ResponseBinding, ResponseFamily,
    Store, body_instances_in_rows, body_key_in, carrier_row, prune_retired_bodies_in_rows,
    require_body_instances,
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
/// it deletes and the ones it rewrites, the inline ASSETs it shells and the
/// row-held responses it leaves their erased disposition.
struct ArchivePrune {
    deleted: BTreeSet<Vec<u8>>,
    rewritten: Vec<(Vec<u8>, Vec<u8>)>,
    assets: BTreeSet<EntityId>,
    responses: BTreeSet<Vec<u8>>,
    /// The body rows that stay, read back under the forked custody.
    kept: Rows,
}

impl ArchivePrune {
    /// The prune of the `retired` instances among `rows`, as a restore
    /// prunes an image's.
    fn of(rows: &Rows, retired: &BTreeSet<[u8; 16]>) -> Result<Self> {
        let mut kept = rows.clone();
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
        Ok(Self {
            deleted,
            rewritten,
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
    /// Returns the claim-bound decisions dropped because their keys stayed
    /// on another host, by id (hex), as a restore's report names them.
    pub(crate) fn activate_archived(&self, source: &LiveCustody) -> Result<Vec<String>> {
        let rows = {
            let txn = self.env.read_txn()?;
            let mark = ARCHIVED.get(self, &txn, &())?;
            if !archived_by(mark.as_deref(), self.env.path())? {
                return Err(Error::InvalidConfig("this vault is not archived".into()));
            }
            let mut prefixes = live_custody_prefixes();
            prefixes.push(GATE_DECISION_KEY_PREFIX);
            prefixes.extend(body_prefixes());
            vault_meta_rows(&self.env, &txn, &prefixes)?
        };
        let mut custody = preflight_checkpoint_rows(&rows, Some(source))?;
        // Its body instances fork with its claim keys (KS-2A): a missing one
        // refuses; a retired one's rows go before the archive is lifted.
        let retired = require_body_instances(&body_instances_in_rows(&rows)?, custody.plan_mut())?;
        let prune = ArchivePrune::of(&rows, &retired)?;
        // The environment's path is the canonical root it was opened at.
        let root = self.env.path().to_path_buf();
        refuse_custody_beside(&root)?;
        #[cfg(test)]
        if let Some(callback) = BEFORE_ACTIVATION_FORK.with(|slot| slot.borrow_mut().take()) {
            callback();
        }
        let mut wtxn = self.env.past_seal_write_txn()?;
        let forked = self.fork_gate_custody_to_in_txn(&mut wtxn, &custody, &root)?;
        let committed = self
            .prune_bodies_in_txn(&mut wtxn, &prune)
            .and_then(|()| self.drop_erased_gate_decisions_in_txn(&mut wtxn, custody.erased()))
            .and_then(|()| self.read_back_in_txn(&wtxn))
            .and_then(|()| self.read_back_bodies_in_txn(&wtxn, &prune.kept))
            .and_then(|()| crate::identity::drop_machine_identity_in_txn(self, &mut wtxn))
            // The orders standing on its source now, not the ones it had.
            .and_then(|()| replace_host_holds_in_txn(self, &mut wtxn, source.host_holds()))
            .and_then(|()| ARCHIVED.delete(self, &mut wtxn, &()))
            .and_then(|_| Ok(wtxn.commit()?));
        if let Err(err) = committed {
            if let Some(forked) = forked {
                forked.remove();
            }
            return Err(err);
        }
        Ok(custody.lost().iter().map(|(id, _)| id.to_hex()).collect())
    }

    /// Applies `prune` in `wtxn`: its row deletions and rewrites, each
    /// pruned inline ASSET's shell, and each pruned response's erased
    /// disposition.
    fn prune_bodies_in_txn(&self, wtxn: &mut heed::RwTxn<'_>, prune: &ArchivePrune) -> Result<()> {
        destination::delete_vault_meta_in_txn(&self.env, wtxn, &prune.deleted)?;
        for (key, value) in &prune.rewritten {
            self.side_vault_meta().put(wtxn, key, value)?;
        }
        if !prune.assets.is_empty() {
            let at = crate::ports::recorded_at_in_txn(self, wtxn)?;
            for entity in &prune.assets {
                self.port_entity_scrub(wtxn, entity, ScrubbedRecord::Shell, at)?;
            }
        }
        for carrier in &prune.responses {
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
            if let Some(carriage) = family.carriage(&value) {
                family.retire_in_txn(self, wtxn, key, &carriage)?;
            }
        }
        Ok(())
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
