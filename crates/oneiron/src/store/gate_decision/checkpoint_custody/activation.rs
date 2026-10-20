//! An owner's activation of an archived vault as a side vault of the vault
//! that replaced it (moved out of the checkpoint custody module whole).

use heed::RoTxn;

use super::super::ledger::LEDGER;
#[cfg(test)]
use super::BEFORE_ACTIVATION_FORK;
use super::{
    ARCHIVED, GATE_DECISION_KEY_PREFIX, GateDecisionId, LiveCustody, archived_by, corrupt,
    destination, live_custody_prefixes, orcb, preflight_checkpoint_rows, refuse_custody_beside,
    replace_host_holds_in_txn, vault_meta_rows,
};
use crate::error::{Error, Result};
use crate::store::key_custody::{self, LocalCustody};
use crate::store::{
    BODY_KEYS, INLINE_ASSETS, Store, body_instances_in_rows, prune_retired_bodies_in_rows,
    require_body_instances,
};

impl Store {
    /// An owner's activation of this archived vault as a side vault of the
    /// vault whose live custody state is `source`, the one that replaced it.
    /// Its custody forks as a side restore's does, into a directory of its
    /// own beside its root: every receipt it holds is checked against the
    /// custody it binds to first, a key `source` destroyed or has committed
    /// to destroy is not copied and the receipts under it are dropped, every
    /// receipt it keeps is read back under the forked keys, and only then
    /// does the new binding commit, with the archive mark lifted and this
    /// install's machine identity dropped, the replacement keeping it. Anything
    /// short of that leaves it archived, as it was. The caller reopens the
    /// vault, whose handles then shred only its own keys.
    pub(crate) fn activate_archived(&self, source: &LiveCustody) -> Result<()> {
        let rows = {
            let txn = self.env.read_txn()?;
            let mark = ARCHIVED.get(self, &txn, &())?;
            if !archived_by(mark.as_deref(), self.env.path())? {
                return Err(Error::InvalidConfig("this vault is not archived".into()));
            }
            let mut prefixes = live_custody_prefixes();
            prefixes.push(GATE_DECISION_KEY_PREFIX);
            prefixes.extend([BODY_KEYS.decl().prefix, INLINE_ASSETS.decl().prefix]);
            vault_meta_rows(&self.env, &txn, &prefixes)?
        };
        let mut custody = preflight_checkpoint_rows(&rows, Some(source))?;
        // Its body instances fork with its claim keys (KS-2A): a missing one
        // refuses; a retired one's rows go before the archive is lifted.
        let retired = require_body_instances(&body_instances_in_rows(&rows)?, custody.plan_mut())?;
        let pruned = prune_retired_bodies_in_rows(&mut rows.clone(), &retired)?.row_keys();
        // The environment's path is the canonical root it was opened at.
        let root = self.env.path().to_path_buf();
        refuse_custody_beside(&root)?;
        #[cfg(test)]
        if let Some(callback) = BEFORE_ACTIVATION_FORK.with(|slot| slot.borrow_mut().take()) {
            callback();
        }
        let mut wtxn = self.env.past_seal_write_txn()?;
        let forked = self.fork_gate_custody_to_in_txn(&mut wtxn, &custody, &root)?;
        let committed = destination::delete_vault_meta_in_txn(&self.env, &mut wtxn, &pruned)
            .and_then(|()| self.drop_erased_gate_decisions_in_txn(&mut wtxn, custody.erased()))
            .and_then(|()| self.read_back_in_txn(&wtxn))
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
