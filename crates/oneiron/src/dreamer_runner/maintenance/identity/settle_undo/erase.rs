//! The erase scrub of one automatic settle's inverse, and the checks its
//! revert makes before it holds a provisional entity again or relinks a
//! span (FIX 8707).
use super::super::erase::{anchor_reads_in_txn, erase_snapshot, stands_in_txn};
use super::super::hints;
use super::{HeldProvisional, MentionChange, SettleInverse};
use crate::tagging::ProvisionalEntity;
use crate::{EntityId, Result, Vault};

impl HeldProvisional {
    /// Takes the entity's row once an erase reaches the entity, its origin
    /// turn or the span its name was read from. True when it changed.
    fn erase_source(&mut self, id: &EntityId) -> bool {
        let reached = self.id == *id
            || self.source.is_some_and(|source| source.names(id))
            || self
                .entity
                .as_ref()
                .is_some_and(|entity| entity.origin == *id);
        reached && self.entity.take().is_some()
    }
}

impl SettleInverse {
    /// Takes what this settle's kept copies hold of the erased `id`: the
    /// ask's copy once its mention is in `id` or no option is left, `id` as
    /// a candidate, a provisional entity's row it reached, a hint's words
    /// from a mention in it, and both hint copies when it is the entity the
    /// settle named. The anchors, the spans' links, the distinct assertions
    /// and the receipt stay. True when it changed.
    pub(in crate::dreamer_runner::maintenance) fn erase_source(&mut self, id: &EntityId) -> bool {
        let mut changed = erase_snapshot(&mut self.ask, id);
        for each in &mut self.provisionals {
            changed |= each.erase_source(id);
        }
        if self.entity == *id {
            changed |= self.hint_before.take().is_some();
            changed |= self.hint_after.take().is_some();
        }
        changed |= hints::erase_snapshot(&mut self.hint_before, id);
        changed |= hints::erase_snapshot(&mut self.hint_after, id);
        changed
    }
}

/// Whether `held`'s row `entity` may be held again: the span its name was
/// read from still reads as the settle saw it, or, when no span read it
/// then, its origin turn stands.
pub(super) fn provisional_reads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    held: &HeldProvisional,
    entity: &ProvisionalEntity,
) -> Result<bool> {
    match &held.source {
        Some(source) => anchor_reads_in_txn(vault, txn, source, &entity.name),
        None => stands_in_txn(&vault.store, txn, &entity.origin),
    }
}

/// Whether `change` may be put back: its turn and message stand, and so
/// does every entity its link named before, so a deleted candidate is not
/// linked again.
pub(super) fn change_stands_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    change: &MentionChange,
) -> Result<bool> {
    for id in [change.turn, change.message]
        .iter()
        .chain(change.before.entities())
    {
        if !stands_in_txn(&vault.store, txn, id)? {
            return Ok(false);
        }
    }
    Ok(true)
}
