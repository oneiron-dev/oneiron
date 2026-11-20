//! Each signer's top rows per sequence scope in a base, so that a fold past
//! it takes only new rows that move no row's sequence floor (`rows_floor`).

use std::collections::BTreeMap;
use std::sync::Arc;

use super::*;

/// Per signer and sequence scope (`world_privacy::side_world`): the highest
/// sequence among the base's rows and the rows at it.
#[derive(Clone, Default)]
pub(super) struct ScopeTops(
    im::OrdMap<(AuthorityKey, Option<EntityId>), Arc<(u64, Vec<AuthorityEntryHash>)>>,
);

impl ScopeTops {
    /// The tops of `rows`.
    pub(super) fn of(rows: &[(AuthorityEntryHash, &AuthorityLogEntry)]) -> Self {
        let mut tops = BTreeMap::<_, (u64, Vec<_>)>::new();
        for (hash, entry) in rows {
            let key = (
                entry.signer_key().clone(),
                super::super::world_privacy::side_world(&entry.op),
            );
            let top = tops.entry(key).or_insert((entry.seq, Vec::new()));
            if entry.seq > top.0 {
                *top = (entry.seq, Vec::new());
            }
            if entry.seq == top.0 {
                top.1.push(*hash);
            }
        }
        Self(
            tops.into_iter()
                .map(|(key, top)| (key, Arc::new(top)))
                .collect(),
        )
    }

    /// The tops with `order`'s rows, the new rows past the base parents
    /// first, added; None where one of them would move a row's floor or
    /// sit past its own. The base holds no row past its floor (`Once::of`),
    /// so each of its rows is an ancestor of every higher row of its signer
    /// and scope. A new main row lies on one chain off the base's one main
    /// head (`side_tail::shape`), so every earlier main row is among its
    /// ancestors, and it need only rise above its signer's top. A new side
    /// row must rise above its signer's top in its world and descend from
    /// every row at it, along that world's rows.
    pub(super) fn past(
        &self,
        base_rows: &BaseRows,
        new_rows: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
        order: &[AuthorityEntryHash],
    ) -> Option<Self> {
        let mut tops = self.0.clone();
        for hash in order {
            let entry = new_rows[hash];
            let world = super::super::world_privacy::side_world(&entry.op);
            let key = (entry.signer_key().clone(), world);
            if let Some(top) = tops.get(&key) {
                let (top_seq, top_rows) = &**top;
                let row = |hash: &AuthorityEntryHash| match new_rows.get(hash) {
                    Some(entry) => Some((
                        entry.parent_hashes.as_slice(),
                        super::super::world_privacy::side_world(&entry.op),
                    )),
                    None => base_rows
                        .get(hash)
                        .map(|row| (row.parents.as_slice(), row.world)),
                };
                if entry.seq <= *top_seq
                    || (world.is_some()
                        && !top_rows.iter().all(|top_row| {
                            super::super::rows_floor::descends_within_scope(
                                top_row,
                                &entry.parent_hashes,
                                world,
                                row,
                            )
                        }))
                {
                    return None;
                }
            }
            tops.insert(key, Arc::new((entry.seq, vec![*hash])));
        }
        Some(Self(tops))
    }
}
