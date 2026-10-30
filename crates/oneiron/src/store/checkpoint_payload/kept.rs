//! What the kept copies of a vault's checkpoints still need of its payload
//! leaves (KS7-5): each compartment's generations, by the copies that name
//! them, read from every kept copy's inventory. A retention retirement of a
//! leaf waits while a kept copy names a generation at or below it; an
//! inventory that did not read leaves the set incomplete, and an incomplete
//! set releases nothing. It only ever delays a key, never a user act
//! (Engine 10-20 08:4x, ruling 3).

use std::collections::{BTreeMap, BTreeSet};

use super::PayloadItem;

/// Every generation of every compartment a kept copy names, with the
/// checkpoint ids of the copies naming it.
#[derive(Debug, Default)]
pub(crate) struct KeptGenerations {
    named: BTreeMap<PayloadItem, BTreeMap<u64, BTreeSet<[u8; 32]>>>,
    incomplete: bool,
}

impl KeptGenerations {
    /// Records that the kept copy `holder` (its checkpoint id) needs
    /// `item`'s leaf at `generation`.
    pub(crate) fn hold(&mut self, item: PayloadItem, generation: u64, holder: [u8; 32]) {
        self.named
            .entry(item)
            .or_default()
            .entry(generation)
            .or_default()
            .insert(holder);
    }

    /// Records that a kept copy's inventory did not read: nothing it may
    /// name is released.
    pub(crate) fn unread(&mut self) {
        self.incomplete = true;
    }

    /// Whether no kept copy needs `item`'s leaf at or below `through`.
    pub(crate) fn releases(&self, item: &PayloadItem, through: u64) -> bool {
        !self.incomplete
            && self
                .named
                .get(item)
                .is_none_or(|generations| generations.range(..=through).next().is_none())
    }
}
