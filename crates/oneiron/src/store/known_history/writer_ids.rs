//! A writer's known-value history read with the ids it was read from (FIX
//! 12210): what a later pass in the same writer checks the index built
//! from it against, before it uses that index again.

use std::sync::Arc;

use heed::RwTxn;

use super::{
    HISTORY, INDEX, KnownHistory, KnownHistoryIds, copy_master, index_subject, read_entries,
};
use crate::error::Result;
use crate::store::Store;

impl Store {
    /// [`Store::known_history_in_writer`], read the same way, with the ids
    /// it read: the custody binding, the master's generation and each
    /// holder's committed slots.
    ///
    /// # Errors
    ///
    /// As [`Store::known_history_in_writer`].
    pub(crate) fn known_history_with_ids_in_writer(
        &self,
        wtxn: &RwTxn<'_>,
    ) -> Result<Option<(KnownHistory, KnownHistoryIds)>> {
        let Some(index) = INDEX.get(self, wtxn, &())? else {
            return Ok(None);
        };
        let custody = self.core.key_custody.bind_in_txn(self, wtxn)?;
        let master = copy_master(&custody.read(&index_subject(custody.binding())?.at(index))?)?;
        let mut holders = Vec::new();
        let mut ids = Vec::new();
        for (holder, refs) in HISTORY.scan(self, wtxn)? {
            let slots: Vec<u64> = refs.slots().collect();
            let entries = read_entries(custody, &holder, slots.iter().copied())?;
            if !entries.is_empty() {
                holders.push((holder, entries));
            }
            ids.push((holder, slots));
        }
        let ids = KnownHistoryIds {
            core: Arc::downgrade(&self.core),
            binding: custody.binding().clone(),
            index,
            holders: ids,
        };
        Ok(Some((KnownHistory { master, holders }, ids)))
    }
}

impl KnownHistoryIds {
    /// Whether `other` names the same history: the same custody binding,
    /// master generation and committed slots, holder by holder. Custody
    /// never writes other bytes at a slot it holds, so two such reads name
    /// the same entries.
    pub(crate) fn names_same_history(&self, other: &Self) -> bool {
        self.binding == other.binding && self.index == other.index && self.holders == other.holders
    }
}
