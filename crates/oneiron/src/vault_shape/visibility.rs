//! What the visible shape APIs read of the seed and the open applies (FIX
//! 10199). The live rows were always read through the caller's read; the
//! stored seed, the open apply journals and their count are now read through
//! it too, so a reader never learns a hidden world's name or a hidden setup
//! change from a declaration that never passed the visibility check. A row
//! is withheld when it names structure `visible` hides every entity of, or a
//! person or manifest `visible` hides; settings no entity backs are never
//! withheld. A withheld declaration is not missing structure: it is never
//! planned as a create, and this caller's apply keeps it in the stored seed
//! rather than dropping it. The trusted host's `shape_read` stays
//! unrestricted.
//!
//! The carriers are read through it as well (FIX 9960): a stored seed whose
//! revision row or author `visible` hides is no seed to this caller, a
//! parent revision it hides is named nowhere, an open apply whose author or
//! seed revision it hides is not listed or counted, and a plan names the
//! stored seed's id only to a caller that reads the whole seed. A check that
//! cannot be read leaves the projection as it was before it.
use std::collections::BTreeSet;

use super::apply::ShapeApplyReceipt;
use super::seed::StoredShapeSeed;
use super::{ShapeRow, ShapeSeed, ShapeTarget};
use crate::error::Result;
use crate::vault::live_entity_row_in_txn;
use crate::{EntityId, Vault};

/// The entity a target names outright, beside the ones it resolves to.
fn named_entity(target: &ShapeTarget) -> Option<EntityId> {
    match target {
        ShapeTarget::Member { member: person } | ShapeTarget::Facet { person, .. } => {
            EntityId::from_hex(person).ok()
        }
        ShapeTarget::Manifest { manifest_ref } => EntityId::from_hex(manifest_ref).ok(),
        _ => None,
    }
}

impl Vault {
    /// Whether `target` is withheld from the caller `visible` reads for:
    /// `withheld` hides it, or it names a live entity `visible` hides.
    pub(super) fn shape_target_withheld(
        &self,
        txn: &heed::RoTxn<'_>,
        target: &ShapeTarget,
        withheld: &BTreeSet<ShapeTarget>,
        visible: &mut dyn FnMut(&EntityId) -> Result<bool>,
    ) -> Result<bool> {
        if withheld.contains(target) {
            return Ok(true);
        }
        let Some(id) = named_entity(target) else {
            return Ok(false);
        };
        Ok(live_entity_row_in_txn(&self.store, txn, &id)?.is_live() && !visible(&id)?)
    }

    /// `seed` without the rows withheld from the caller.
    pub(super) fn visible_seed(
        &self,
        seed: &ShapeSeed,
        withheld: &BTreeSet<ShapeTarget>,
        visible: &mut dyn FnMut(&EntityId) -> Result<bool>,
    ) -> Result<ShapeSeed> {
        let txn = self.store.env.read_txn()?;
        let mut rows = Vec::with_capacity(seed.rows.len());
        for row in &seed.rows {
            if !self.shape_target_withheld(&txn, &row.target(), withheld, visible)? {
                rows.push(row.clone());
            }
        }
        Ok(ShapeSeed { rows })
    }

    /// The stored seed and the open applies as `visible` admits them: each
    /// seed row and journal item withheld from the caller left out, with its
    /// run row, and a journal with nothing left counted nowhere.
    pub(super) fn visible_seed_and_applies(
        &self,
        withheld: &BTreeSet<ShapeTarget>,
        visible: &mut dyn FnMut(&EntityId) -> Result<bool>,
    ) -> Result<(Option<StoredShapeSeed>, Vec<ShapeApplyReceipt>)> {
        let seed = match self.shape_seed()? {
            Some(mut stored) => {
                let txn = self.store.env.read_txn()?;
                if self.seed_carrier_withheld(&txn, &stored, visible) {
                    None
                } else {
                    if stored
                        .parent
                        .as_deref()
                        .is_some_and(|parent| self.positively_hidden(&txn, parent, visible))
                    {
                        stored.parent = None;
                    }
                    drop(txn);
                    stored.seed = self.visible_seed(&stored.seed, withheld, visible)?;
                    Some(stored)
                }
            }
            None => None,
        };
        let txn = self.store.env.read_txn()?;
        let mut applies = Vec::new();
        for journal in self.open_shape_applies()? {
            applies.extend(self.visible_journal(&txn, journal, withheld, visible)?);
        }
        Ok((seed, applies))
    }

    /// `journal` as `visible` admits it: none when its author or the seed
    /// revision it stored is hidden from the caller, else its items withheld
    /// from the caller left out, with their run rows, and none when nothing
    /// is left.
    fn visible_journal(
        &self,
        txn: &heed::RoTxn<'_>,
        mut journal: ShapeApplyReceipt,
        withheld: &BTreeSet<ShapeTarget>,
        visible: &mut dyn FnMut(&EntityId) -> Result<bool>,
    ) -> Result<Option<ShapeApplyReceipt>> {
        if self.positively_hidden(txn, &journal.author, visible)
            || self.positively_hidden(txn, &journal.seed_id, visible)
        {
            return Ok(None);
        }
        let mut items = Vec::with_capacity(journal.items.len());
        let mut runs = Vec::with_capacity(journal.run.items.len());
        for (at, entry) in journal.items.into_iter().enumerate() {
            if self.shape_target_withheld(txn, &entry.item.target, withheld, visible)? {
                continue;
            }
            runs.extend(journal.run.items.get(at).cloned());
            items.push(entry);
        }
        if items.is_empty() {
            return Ok(None);
        }
        journal.items = items;
        journal.run.items = runs;
        Ok(Some(journal))
    }

    /// The open apply at `frontier` as `visible` admits it, as
    /// `vault.shape.read` lists it (FIX 9960): what a plan's card shows. The
    /// raw journal stays the resume's and the owner inbox's.
    ///
    /// # Errors
    ///
    /// A read failure, an undecodable setup row, or `visible`'s own.
    pub fn shape_apply_visible(
        &self,
        frontier: &str,
        visible: &mut dyn FnMut(&EntityId) -> Result<bool>,
    ) -> Result<Option<ShapeApplyReceipt>> {
        let Some(journal) = self.shape_apply(frontier)? else {
            return Ok(None);
        };
        let withheld = self.read_live_shape(visible)?.withheld;
        let txn = self.store.env.read_txn()?;
        self.visible_journal(&txn, journal, &withheld, visible)
    }

    /// The stored seed's id as a plan may name it to the caller (FIX
    /// 9960): none when its carrier is withheld, and for an `explicit` seed
    /// none unless it is the stored seed and the caller reads every row of
    /// it, so a plan is no test of what a hidden row says.
    pub(super) fn visible_seed_id(
        &self,
        stored: &StoredShapeSeed,
        explicit: Option<&ShapeSeed>,
        withheld: &BTreeSet<ShapeTarget>,
        visible: &mut dyn FnMut(&EntityId) -> Result<bool>,
    ) -> Result<Option<String>> {
        let txn = self.store.env.read_txn()?;
        if self.seed_carrier_withheld(&txn, stored, visible) {
            return Ok(None);
        }
        drop(txn);
        let Some(explicit) = explicit else {
            return Ok(Some(stored.id.clone()));
        };
        let whole = self
            .visible_seed(&stored.seed, withheld, visible)
            .map_or(true, |seen| seen == stored.seed);
        Ok((stored.seed == *explicit && whole).then(|| stored.id.clone()))
    }

    /// Whether the stored seed revision `stored` is withheld from the
    /// caller: `visible` hides its revision row or its author.
    fn seed_carrier_withheld(
        &self,
        txn: &heed::RoTxn<'_>,
        stored: &StoredShapeSeed,
        visible: &mut dyn FnMut(&EntityId) -> Result<bool>,
    ) -> bool {
        self.positively_hidden(txn, &stored.id, visible)
            || self.positively_hidden(txn, &stored.author, visible)
    }

    /// Whether the hex `id` names a live entity `visible` hides. An id that
    /// names no live entity, or a check that fails, hides nothing.
    fn positively_hidden(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &str,
        visible: &mut dyn FnMut(&EntityId) -> Result<bool>,
    ) -> bool {
        let Ok(id) = EntityId::from_hex(id) else {
            return false;
        };
        live_entity_row_in_txn(&self.store, txn, &id).is_ok_and(|row| row.is_live())
            && matches!(visible(&id), Ok(false))
    }

    /// The seed this caller's apply stores: `seed`, then each stored row
    /// withheld from the caller that `seed` does not name, so an apply never
    /// drops a declaration its caller could not see.
    pub(super) fn seed_keeping_withheld(
        &self,
        seed: &ShapeSeed,
        visible: &mut dyn FnMut(&EntityId) -> Result<bool>,
    ) -> Result<ShapeSeed> {
        let Some(stored) = self.shape_seed()? else {
            return Ok(seed.clone());
        };
        let withheld = self.read_live_shape(visible)?.withheld;
        let named: BTreeSet<ShapeTarget> = seed.rows.iter().map(ShapeRow::target).collect();
        let txn = self.store.env.read_txn()?;
        let mut rows = seed.rows.clone();
        for row in stored.seed.rows {
            let target = row.target();
            if !named.contains(&target)
                && self.shape_target_withheld(&txn, &target, &withheld, visible)?
            {
                rows.push(row);
            }
        }
        Ok(ShapeSeed { rows })
    }
}
